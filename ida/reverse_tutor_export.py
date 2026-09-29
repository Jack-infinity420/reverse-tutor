# -*- coding: utf-8 -*-
"""
Reverse Tutor export bridge for IDA Pro.

What this script is
-------------------
A ~200-line IDAPython script the student runs from inside IDA Pro so their tutor
can see the function they are actually reading. It reads the open IDA database
and writes ONE JSON file. It does not analyse anything the student has not already
opened, it does not read any other file, it does not execute a shell, and it never
touches the network.

How a student runs it
---------------------
1. Open the challenge binary in IDA Pro and let auto-analysis finish.
2. Click inside the function to discuss.
3. Run this script, any of these ways:

   * ``File > Script file...`` and choose this file;
   * or paste into the IDA Python console at the bottom of the window::

         exec(open(r"<path to reverse_tutor_export.py>").read())

   * or copy it into IDA's ``plugins`` directory and use
     ``Edit > Plugins > Reverse Tutor: export context``.

4. The script reports the output path in IDA's message window.

Where the output goes
---------------------
Resolution order, first match wins:

1. the ``REVERSE_TUTOR_OUTPUT`` environment variable,
2. ``rt_bridge.json`` sitting beside the binary (written by ``reverse_build``);
   its ``outputPath`` field is used,
3. ``ida_context.json`` beside the binary,
4. ``ida_context.json`` in the current working directory.

Nothing else is ever written.

Version compatibility
---------------------
The script targets IDA 7.x through 9.x. Every IDA module import is guarded, and
the decompiler is optional: without Hex-Rays the export still carries the
function name, boundaries, disassembly, cross-references, and referenced strings,
with ``pseudocode: null``.
"""

from __future__ import print_function

import json
import os
import sys
import time

# --------------------------------------------------------------------------
# IDA imports, each guarded: the export must degrade rather than fail.
# --------------------------------------------------------------------------

ida_kernwin = None
ida_funcs = None
ida_lines = None
ida_name = None
ida_xref = None
ida_bytes = None
ida_segment = None
ida_nalt = None
ida_hexrays = None
idaapi = None
idc = None

try:
    import ida_kernwin
except ImportError:
    pass
try:
    import ida_funcs
except ImportError:
    pass
try:
    import ida_lines
except ImportError:
    pass
try:
    import ida_name
except ImportError:
    pass
try:
    import ida_xref
except ImportError:
    pass
try:
    import ida_bytes
except ImportError:
    pass
try:
    import ida_segment
except ImportError:
    pass
try:
    import ida_nalt
except ImportError:
    pass
try:
    import idaapi
except ImportError:
    pass
try:
    import idc
except ImportError:
    pass
try:
    # Optional: only present when the Hex-Rays decompiler is installed and
    # licensed. Its absence is a supported configuration, not an error.
    import ida_hexrays
except ImportError:
    ida_hexrays = None


SCHEMA = "reverse-tutor/ida-context/v1"
MAX_ASSEMBLY = 400
MAX_PSEUDOCODE_CHARS = 8000
MAX_STRINGS = 40
MAX_CALLERS = 40
MAX_CALLEES = 40


def out(message):
    """Report progress in IDA's own output window, and on stdout when run headless."""
    try:
        if ida_kernwin is not None:
            ida_kernwin.msg("[reverse-tutor] %s\n" % message)
    except Exception:
        pass
    try:
        print("[reverse-tutor] %s" % message)
    except Exception:
        pass


def hexea(ea):
    """Render an address the way IDA does, so the tutor's questions match the UI."""
    try:
        return "0x%X" % int(ea)
    except Exception:
        return None


def get_cursor_ea():
    """Current cursor address, or the screen address as a fallback."""
    if ida_kernwin is not None:
        try:
            return ida_kernwin.get_screen_ea()
        except Exception:
            pass
    if idc is not None:
        try:
            return idc.here()
        except Exception:
            pass
    return None


def get_current_function(ea):
    """Function containing ``ea``, or None."""
    if ida_funcs is None or ea is None:
        return None
    try:
        return ida_funcs.get_func(ea)
    except Exception:
        return None


def function_name(func, ea):
    """Best available name for a function: IDA's name, else a synthesised one."""
    try:
        if ida_name is not None:
            name = ida_name.get_name(func.start_ea)
            if name:
                return name
        if ida_funcs is not None:
            name = ida_funcs.get_func_name(func.start_ea)
            if name:
                return name
    except Exception:
        pass
    return "sub_%X" % int(ea)


def get_assembly(func):
    """
    Disassemble the function instruction by instruction.

    Uses the same line generator IDA's listing uses, so what the tutor sees is
    what the student sees, including IDA's own naming for sub-functions.
    """
    result = []
    if func is None:
        return result
    ea = func.start_ea
    end = func.end_ea
    guard = 0
    while ea < end and len(result) < MAX_ASSEMBLY and guard < MAX_ASSEMBLY * 8:
        guard += 1
        text = None
        try:
            if ida_lines is not None:
                force_code = getattr(ida_lines, "GENDSM_FORCE_CODE", 0)
                text = ida_lines.generate_disasm_line(ea, force_code)
                if text is not None:
                    text = ida_lines.tag_remove(text)
        except Exception:
            text = None
        if text is None and idc is not None:
            try:
                text = idc.generate_disasm_line(ea, 0)
            except Exception:
                text = None
        if text is None:
            break
        result.append({"address": hexea(ea), "text": text})

        # Advance to the next instruction, tolerating every API shape IDA ships.
        next_ea = None
        try:
            if idc is not None:
                next_ea = idc.next_head(ea, end)
        except Exception:
            next_ea = None
        if next_ea is None and ida_bytes is not None:
            try:
                next_ea = ida_bytes.next_head(ea, end)
            except Exception:
                next_ea = None
        if next_ea is None or next_ea <= ea:
            break
        ea = next_ea
    return result


def get_pseudocode(func):
    """
    Hex-Rays pseudocode for the function, or None.

    Pseudocode is exported as an *aid*, never as ground truth: the tutor is told
    to send the student back to the disassembly whenever the two disagree.
    """
    if ida_hexrays is None or func is None:
        return None
    try:
        if not ida_hexrays.init_hexrays_plugin():
            return None
    except Exception:
        return None
    try:
        cfunc = ida_hexrays.decompile(func.start_ea)
        if cfunc is None:
            return None
        text = str(cfunc)
        if len(text) > MAX_PSEUDOCODE_CHARS:
            text = text[:MAX_PSEUDOCODE_CHARS] + "\n/* ... truncated by reverse-tutor ... */"
        return text
    except Exception:
        return None


def get_callers(func):
    """Names or addresses of the callers of ``func``."""
    result = []
    if func is None or ida_xref is None:
        return result
    try:
        ea = func.start_ea
        xref = ida_xref.get_first_cref_to(ea)
        while xref is not None and xref != idaapi.BADADDR and len(result) < MAX_CALLERS:
            result.append(describe_address(xref))
            xref = ida_xref.get_next_cref_to(ea, xref)
    except Exception:
        pass
    return result


def get_callees(func):
    """Names or addresses of the functions this function calls."""
    result = []
    if func is None or ida_xref is None:
        return result
    try:
        ea = func.start_ea
        while ea < func.end_ea and len(result) < MAX_CALLEES:
            if ida_funcs is not None and ida_funcs.get_func(ea) is None:
                ea += 1
                continue
            xref = ida_xref.get_first_cref_from(ea)
            while xref is not None and xref != idaapi.BADADDR:
                description = describe_address(xref)
                if description not in result:
                    result.append(description)
                if len(result) >= MAX_CALLEES:
                    break
                xref = ida_xref.get_next_cref_from(ea, xref)
            next_ea = None
            if idc is not None:
                try:
                    next_ea = idc.next_head(ea, func.end_ea)
                except Exception:
                    next_ea = None
            if next_ea is None or next_ea <= ea:
                break
            ea = next_ea
    except Exception:
        pass
    return result


def describe_address(ea):
    """A symbol name when IDA has one for ``ea``, else the raw address."""
    try:
        if ida_funcs is not None:
            func = ida_funcs.get_func(ea)
            if func is not None and func.start_ea == ea:
                return function_name(func, ea)
        if ida_name is not None:
            name = ida_name.get_name(ea)
            if name:
                return name
    except Exception:
        pass
    return hexea(ea)


def get_referenced_strings(func):
    """String literals referenced inside the function."""
    result = []
    if func is None or ida_xref is None:
        return result
    try:
        ea = func.start_ea
        while ea < func.end_ea and len(result) < MAX_STRINGS:
            xref = ida_xref.get_first_dref_from(ea)
            while xref is not None and xref != idaapi.BADADDR:
                text = read_string(xref)
                if text and text not in result:
                    result.append(text)
                if len(result) >= MAX_STRINGS:
                    break
                xref = ida_xref.get_next_dref_from(ea, xref)
            next_ea = None
            if idc is not None:
                try:
                    next_ea = idc.next_head(ea, func.end_ea)
                except Exception:
                    next_ea = None
            if next_ea is None or next_ea <= ea:
                break
            ea = next_ea
    except Exception:
        pass
    return result


def read_string(ea):
    """A printable ASCII string starting at ``ea``, or None."""
    getter = None
    if idc is not None:
        getter = getattr(idc, "get_strlit_contents", None) or getattr(idc, "GetString", None)
    if getter is None and ida_bytes is not None:
        getter = getattr(ida_bytes, "get_strlit_contents", None)
    if getter is None:
        return None
    try:
        raw = getter(ea, -1, 0)
    except TypeError:
        try:
            raw = getter(ea)
        except Exception:
            return None
    except Exception:
        return None
    if not raw:
        return None
    if isinstance(raw, bytes):
        try:
            raw = raw.decode("utf-8", "replace")
        except Exception:
            return None
    text = "".join(character for character in raw if 32 <= ord(character) < 127)
    return text if len(text) >= 4 else None


def binary_info():
    """Name and architecture of the database under analysis."""
    name = None
    path = None
    if ida_nalt is not None:
        try:
            path = ida_nalt.get_input_file_path()
            name = os.path.basename(path) if path else None
        except Exception:
            pass
    if name is None and idc is not None:
        try:
            path = idc.get_input_file_path()
            name = os.path.basename(path) if path else None
        except Exception:
            pass
    architecture = None
    if idaapi is not None:
        try:
            info = idaapi.get_inf_structure()
            architecture = "64" if getattr(info, "is_64bit", lambda: False)() else "32"
        except Exception:
            architecture = None
    return {
        "name": name,
        "path": path,
        "architecture": architecture,
        "processor": processor_name(),
    }


def processor_name():
    if idaapi is not None:
        try:
            info = idaapi.get_inf_structure()
            return getattr(info, "procname", None)
        except Exception:
            pass
    return None


def resolve_output_path():
    """
    Decide where to write, using only the documented search order.

    The bridge never walks the filesystem and never writes to more than one path.
    """
    override = os.environ.get("REVERSE_TUTOR_OUTPUT")
    if override:
        return override

    candidate_dirs = []
    path = None
    if ida_nalt is not None:
        try:
            path = ida_nalt.get_input_file_path()
        except Exception:
            path = None
    if path:
        candidate_dirs.append(os.path.dirname(path))
    candidate_dirs.append(os.getcwd())

    for directory in candidate_dirs:
        if not directory:
            continue
        bridge = os.path.join(directory, "rt_bridge.json")
        if os.path.isfile(bridge):
            try:
                with open(bridge, "r") as handle:
                    data = json.load(handle)
                target = data.get("outputPath")
                if target:
                    return target
            except Exception:
                pass
        # No bridge file here: fall back to the plain name in this directory and
        # stop, rather than continuing to the next candidate.
        return os.path.join(directory, "ida_context.json")
    return os.path.join(os.getcwd(), "ida_context.json")


def collect():
    """Build the export payload from the current IDA database."""
    ea = get_cursor_ea()
    func = get_current_function(ea)

    payload = {
        "schema": SCHEMA,
        "exportedAt": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "exporter": "reverse_tutor_export.py",
        "binary": binary_info(),
        "cursor": {"address": hexea(ea)},
        "currentFunction": None,
        "assembly": [],
        "pseudocode": None,
        "callers": [],
        "callees": [],
        "strings": [],
        "decompilerAvailable": ida_hexrays is not None,
    }

    if func is None:
        payload["note"] = (
            "The cursor is not inside a recognised function. Click inside the function "
            "you want to discuss and run the export again."
        )
        return payload, None

    payload["currentFunction"] = {
        "name": function_name(func, ea),
        "start": hexea(func.start_ea),
        "end": hexea(func.end_ea),
        "size": int(func.end_ea) - int(func.start_ea),
        "cursorInside": hexea(ea),
    }
    payload["assembly"] = get_assembly(func)
    payload["pseudocode"] = get_pseudocode(func)
    payload["callers"] = get_callers(func)
    payload["callees"] = get_callees(func)
    payload["strings"] = get_referenced_strings(func)
    return payload, func


def write_payload(payload, output_path):
    """Write the payload atomically: a temp file in the same directory, then rename."""
    directory = os.path.dirname(output_path) or "."
    try:
        if not os.path.isdir(directory):
            os.makedirs(directory)
    except Exception:
        pass
    temp = "%s.tmp%d" % (output_path, os.getpid())
    with open(temp, "w") as handle:
        json.dump(payload, handle, ensure_ascii=False, indent=2, sort_keys=False)
    try:
        if os.path.exists(output_path):
            os.remove(output_path)
        os.rename(temp, output_path)
    except Exception:
        # Some filesystems refuse the rename dance; the temp file is still valid JSON.
        output_path = temp
    return output_path


def export():
    """Run the export. Returns the path written, or None when nothing was written."""
    payload, func = collect()
    output_path = resolve_output_path()
    written = write_payload(payload, output_path)

    if func is None:
        out("nothing to export: put the cursor inside a function first")
        out("wrote %s (with a note explaining the problem)" % written)
        return written

    out(
        "exported %s [%s..%s]: %d instructions, %d callers, %d callees, pseudocode=%s"
        % (
            payload["currentFunction"]["name"],
            payload["currentFunction"]["start"],
            payload["currentFunction"]["end"],
            len(payload["assembly"]),
            len(payload["callers"]),
            len(payload["callees"]),
            "yes" if payload["pseudocode"] else "no",
        )
    )
    out("wrote %s" % written)
    return written


# --------------------------------------------------------------------------
# Plugin wrapper, so the script can also be dropped into IDA's plugins folder.
# --------------------------------------------------------------------------

if idaapi is not None:
    class ReverseTutorExport(idaapi.plugin_t):
        flags = idaapi.PLUGIN_KEEP
        comment = "Export the current function for the Reverse Tutor"
        help = "Writes ida_context.json beside the binary so the tutor can read it."
        wanted_name = "Reverse Tutor: export context"
        wanted_hotkey = "Ctrl-Shift-E"

        def init(self):
            return idaapi.PLUGIN_OK

        def run(self, arg):
            try:
                export()
            except Exception as error:  # noqa: BLE001 - report, never crash IDA
                out("export failed: %s" % error)

        def term(self):
            pass


    def PLUGIN_ENTRY():  # noqa: N802 - IDA's required entry point name
        return ReverseTutorExport()


if __name__ == "__main__":
    # Running this file directly (headless: `idat64 -A -S"reverse_tutor_export.py" binary`)
    # exports once and exits. Running it via IDA's script menu does the same.
    try:
        export()
    except Exception as error:  # noqa: BLE001
        out("export failed: %s" % error)
        sys.exit(1)
