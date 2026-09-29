/**
 * Cross-toolchain discovery and bounded process execution.
 *
 * ## The target is 32-bit, on purpose
 *
 * The audience is a student practising **x86 32-bit** reverse engineering in
 * `ida.exe` (IDA's 32-bit build, which loads only 32-bit files). A 64-bit ELF would
 * be rejected by that IDA outright, so everything this plugin emits is
 * `ELF32 / Intel 80386`.
 *
 * That choice reaches further than the compiler flag:
 *
 * - i386 Linux has no `syscall` instruction; kernel services go through
 *   `int 0x80` with the number in `EAX` and arguments in `EBX, ECX, EDX, ESI,
 *   EDI, EBP`.
 * - The calling convention is **cdecl**, not System V AMD64: arguments arrive on
 *   the stack as `[ebp+8]`, `[ebp+0xc]`, `[ebp+0x10]`. The `function-args` template
 *   teaches exactly that, so its source is written in cdecl terms.
 * - Registers are `EAX`-width; pointers are 4 bytes; `long` is 32 bits.
 *
 * ## Why cross-compiling works from a Windows host
 *
 * The challenge is *freestanding* — no libc header, no libc linked — so clang+lld
 * can emit the ELF without any i386 Linux sysroot.
 *
 * Two Windows gotchas are handled here and are the reason this module exists:
 *
 * 1. `clang` defaults to linking a PE image even under `--target=i386-linux-gnu`;
 *    the bundled `ld.lld` is what actually produces the ELF, so it is probed with
 *    a real compile rather than by version string.
 * 2. A toolchain whose install path contains characters the MSYS2 runtime cannot
 *    map (this deployment's `%USERPROFILE%` is non-ASCII) fails inside `cc1` with
 *    "No such file or directory" for files that plainly exist. Every invocation
 *    therefore runs with TMP/TEMP/TMPDIR pinned to an ASCII-only directory.
 *
 * @module dsh-reverse-tutor/challenge/toolchain
 */

import { spawn, spawnSync } from 'node:child_process'
import type { StdioOptions } from 'node:child_process'
import { closeSync, existsSync, mkdtempSync, openSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { dirname, isAbsolute, join } from 'node:path'
import { ensureDir, shortPath, tutorRoot } from '../policy.js'

/** The one architecture this plugin targets, and the IDA edition it pairs with. */
export const TARGET = {
  /** clang/gcc target triple. */
  triple: 'i386-linux-gnu',
  /** Human label used in tool results and the student brief. */
  label: 'ELF32 i386 (x86 32-bit)',
  /** ELF `e_machine` value: EM_386. */
  machine: 3,
  /** ELF class byte: ELFCLASS32. */
  elfClass: 1,
  /** Pointer width in bytes, for the documents that mention it. */
  pointerSize: 4,
  /** The IDA executable that loads this: its 32-bit build. */
  ida: 'ida.exe',
} as const

/** How to invoke one compiler. */
export interface CompileCommand {
  /** Absolute path of the compiler executable. */
  readonly command: string
  /** Fixed argument vector; `shell` is never used. */
  readonly args: readonly string[]
  /** Human-readable toolchain label for the model. */
  readonly label: string
}

/** A located compiler plus the flags needed to target 32-bit Linux (i386). */
export interface Toolchain {
  readonly command: string
  readonly label: string
  readonly kind: 'clang-lld' | 'gcc-linux' | 'cross-gcc'
  readonly target?: string
}

/** How the accepted value can be checked on this host. */
export type ExecutionKind = 'wsl' | 'native' | 'qemu' | 'none'

/** A runtime able to execute a 32-bit Linux ELF, when one exists. */
export interface ExecutionRuntime {
  readonly kind: ExecutionKind
  readonly label: string
  readonly command?: string
  readonly prefixArgs?: readonly string[]
}

/** The result of one bounded child process. */
export interface ProcessResult {
  readonly code: number | null
  readonly signal: string | null
  readonly stdout: string
  readonly stderr: string
  readonly timedOut: boolean
  readonly spawnError?: string
}

/** Environment overrides for the reverse-tutor toolchain. */
export const COMPILER_ENV = 'DSH_REVERSE_TUTOR_CC'

/**
 * Opt-in switch for the compiler-free emitter.
 *
 * Off by default, and that default is a deliberate teaching decision. A challenge
 * that falls back to `elf.ts` is one flat blob of hand-assembled code: no C function
 * prologues, no cross-function calls, no `cdecl` frame to read. A student sent there
 * to learn function identification or calling conventions is being taught against an
 * artefact that has none of the structure the lesson is about — and the failure that
 * caused it (a compiler that timed out once, a scratch directory an antivirus was
 * holding open) is invisible in the lesson.
 *
 * So: a real compile failure fails the build, loudly, with the compiler's own output.
 * Set `DSH_REVERSE_TUTOR_ALLOW_EMITTER=1` on a host with no Linux-capable compiler to
 * get the emitted artefact back, knowingly.
 */
export const EMITTER_ENV = 'DSH_REVERSE_TUTOR_ALLOW_EMITTER'

/** Whether the deterministic emitter may stand in for a real compile. */
export function emitterAllowed(): boolean {
  const value = process.env[EMITTER_ENV]
  if (value === undefined) return false
  const normalized = value.trim().toLowerCase()
  return normalized === '1' || normalized === 'true' || normalized === 'yes' || normalized === 'on'
}
/** Environment overrides for the runtime used to execute a challenge. */
export const RUNTIME_ENV = 'DSH_REVERSE_TUTOR_RUNNER'

/**
 * The probe compiled to decide whether a candidate toolchain can actually emit a
 * 32-bit Linux ELF.
 *
 * i386 has no `syscall`; `exit(0)` is `int 0x80` with `EAX = 1` and `EBX = 0`. A
 * toolchain that cannot assemble this cannot build any challenge either.
 */
const PROBE_SOURCE = `__attribute__((naked)) void _start(void)
{
    __asm__ volatile("xorl %ebx, %ebx\\n\\tmovl $1, %eax\\n\\tint $0x80\\n\\thlt\\n\\t");
}
`

/**
 * A scratch directory guaranteed to hold only ASCII characters in its path.
 *
 * `os.tmpdir()` is not usable here: this deployment's user profile is
 * non-ASCII, and the MSYS2/LLVM driver cannot create its temporary object files
 * there. The plugin's own root is ASCII whenever `DSH_HOME` is.
 */
export function scratchDir(): string {
  const configured = process.env['DSH_REVERSE_TUTOR_TMP']
  if (configured !== undefined && configured.trim() !== '') return ensureDir(configured)
  const preferred = join(tutorRoot(), 'tmp')
  if (isAscii(preferred)) return ensureDir(preferred)
  const fallback = join(process.env['SystemRoot'] ?? 'C:\\Windows', 'Temp', 'reverse-tutor')
  return ensureDir(fallback)
}

function isAscii(value: string): boolean {
  // eslint-disable-next-line no-control-regex
  return /^[\x20-\x7e]+$/.test(value)
}

/** Environment for a compiler or runtime child process. */
function childEnv(extra: Record<string, string> = {}): NodeJS.ProcessEnv {
  const temp = scratchDir()
  const env: NodeJS.ProcessEnv = { ...process.env, ...extra }
  delete env['DEBUG']
  env['TMP'] = temp
  env['TEMP'] = temp
  env['TMPDIR'] = temp
  return env
}

/**
 * Run a child process with a hard timeout, capturing bounded output.
 *
 * `shell` is always false and arguments are always structured, so neither a
 * caller-supplied path nor a caller-supplied source can reach a command line.
 */
export function runProcess(
  command: string,
  args: readonly string[],
  options: {
    readonly timeoutMs: number
    readonly cwd?: string
    readonly maxOutputChars?: number
    readonly env?: Record<string, string>
    readonly stdin?: string
  },
): Promise<ProcessResult> {
  const maxOutput = options.maxOutputChars ?? 200_000
  return new Promise<ProcessResult>(resolve => {
    let child
    try {
      child = spawn(command, [...args], {
        cwd: options.cwd,
        shell: false,
        windowsHide: true,
        env: childEnv(options.env),
        stdio: ['pipe', 'pipe', 'pipe'],
      })
    } catch (error) {
      // A confined host can refuse pipe creation outright (`spawn EPERM`). The
      // process itself is still allowed to run, so fall back to file-backed stdio
      // rather than reporting "could not start" for a compiler that works.
      if (isPipeDenial(error)) {
        void runProcessUnpiped(command, args, options, maxOutput).then(resolve)
        return
      }
      resolve({
        code: null,
        signal: null,
        stdout: '',
        stderr: '',
        timedOut: false,
        spawnError: error instanceof Error ? error.message : String(error),
      })
      return
    }

    let stdout = ''
    let stderr = ''
    let timedOut = false
    let settled = false

    const append = (current: string, chunk: string): string =>
      current.length >= maxOutput ? current : (current + chunk).slice(0, maxOutput)

    child.stdout?.setEncoding('utf8')
    child.stderr?.setEncoding('utf8')
    child.stdout?.on('data', (chunk: string) => {
      stdout = append(stdout, chunk)
    })
    child.stderr?.on('data', (chunk: string) => {
      stderr = append(stderr, chunk)
    })

    const timer = setTimeout(() => {
      timedOut = true
      try {
        child.kill('SIGKILL')
      } catch {
        /* already gone */
      }
    }, Math.max(250, options.timeoutMs))

    const finish = (code: number | null, signal: string | null, spawnError?: string): void => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      resolve({ code, signal, stdout, stderr, timedOut, ...(spawnError === undefined ? {} : { spawnError }) })
    }

    child.on('error', error => finish(null, null, error.message))
    child.on('close', (code, signal) => finish(code, signal))

    if (options.stdin !== undefined) {
      child.stdin?.on('error', () => {
        /* the child may exit before consuming stdin */
      })
      child.stdin?.end(options.stdin)
    } else {
      child.stdin?.end()
    }
  })
}

/** Whether a spawn failure means "this host refused the pipe", not "no such program". */
function isPipeDenial(error: unknown): boolean {
  const code = (error as { readonly code?: unknown } | null)?.code
  return code === 'EPERM' || code === 'EACCES' || code === 'ENOTSUP'
}

/**
 * Run a child with its output redirected to files instead of pipes.
 *
 * Some confined hosts (DSH's own file sandbox among them) refuse to create the
 * anonymous pipes behind `stdio: 'pipe'` while still allowing the process itself to
 * start. Redirecting to files in the plugin's own scratch directory is the portable
 * way to keep the compiler's diagnostics: without it, detection concludes there is no
 * compiler at all and every challenge would be emitted instead of compiled.
 */
function runProcessUnpiped(
  command: string,
  args: readonly string[],
  options: {
    readonly timeoutMs: number
    readonly cwd?: string
    readonly env?: Record<string, string>
    readonly stdin?: string
  },
  maxOutput: number,
): Promise<ProcessResult> {
  const scratch = ensureDir(join(scratchDir(), 'capture'))
  const stamp = `${process.pid.toString(36)}-${Date.now().toString(36)}-${Math.floor(Math.random() * 1e6).toString(36)}`
  const outPath = join(scratch, `${stamp}.out`)
  const errPath = join(scratch, `${stamp}.err`)

  let child
  let fdOut: number | undefined
  let fdErr: number | undefined
  try {
    fdOut = openSync(outPath, 'w')
    fdErr = openSync(errPath, 'w')
  } catch (error) {
    // Even a capture file is refused: run silently and report only the exit code.
    for (const fd of [fdOut, fdErr]) if (fd !== undefined) { try { closeSync(fd) } catch { /* ignore */ } }
    return runProcessSilently(command, args, options)
  }

  try {
    child = spawn(command, [...args], {
      cwd: options.cwd,
      shell: false,
      windowsHide: true,
      env: childEnv(options.env),
      stdio: ['ignore', fdOut, fdErr],
    })
  } catch (error) {
    safeClose(fdOut, fdErr)
    cleanupFiles(outPath, errPath)
    return Promise.resolve({
      code: null,
      signal: null,
      stdout: '',
      stderr: '',
      timedOut: false,
      spawnError: error instanceof Error ? error.message : String(error),
    })
  }
  safeClose(fdOut, fdErr)

  return new Promise<ProcessResult>(resolve => {
    let timedOut = false
    let settled = false
    const finish = (code: number | null, signal: string | null, spawnError?: string): void => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      resolve({
        code,
        signal,
        stdout: readCaptured(outPath, maxOutput),
        stderr: readCaptured(errPath, maxOutput),
        timedOut,
        ...(spawnError === undefined ? {} : { spawnError }),
      })
      cleanupFiles(outPath, errPath)
    }
    const timer = setTimeout(() => {
      timedOut = true
      try {
        child.kill('SIGKILL')
      } catch {
        /* already gone */
      }
    }, Math.max(250, options.timeoutMs))

    child.on('error', error => finish(null, null, error.message))
    child.on('close', (code, signal) => finish(code, signal))
  })
}

/** Last resort: no pipes, no capture files, exit code only. */
function runProcessSilently(
  command: string,
  args: readonly string[],
  options: { readonly timeoutMs: number; readonly cwd?: string; readonly env?: Record<string, string> },
): Promise<ProcessResult> {
  return new Promise<ProcessResult>(resolve => {
    let child
    try {
      child = spawn(command, [...args], {
        cwd: options.cwd,
        shell: false,
        windowsHide: true,
        env: childEnv(options.env),
        stdio: 'ignore',
      })
    } catch (error) {
      resolve({
        code: null,
        signal: null,
        stdout: '',
        stderr: '',
        timedOut: false,
        spawnError: error instanceof Error ? error.message : String(error),
      })
      return
    }
    let settled = false
    let timedOut = false
    const finish = (code: number | null, signal: string | null, spawnError?: string): void => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      resolve({ code, signal, stdout: '', stderr: '', timedOut, ...(spawnError === undefined ? {} : { spawnError }) })
    }
    const timer = setTimeout(() => {
      timedOut = true
      try {
        child.kill('SIGKILL')
      } catch {
        /* already gone */
      }
    }, Math.max(250, options.timeoutMs))
    child.on('error', error => finish(null, null, error.message))
    child.on('close', (code, signal) => finish(code, signal))
  })
}

function safeClose(...fds: readonly (number | undefined)[]): void {
  for (const fd of fds) {
    if (fd === undefined) continue
    try {
      closeSync(fd)
    } catch {
      /* already closed */
    }
  }
}

function cleanupFiles(...paths: readonly string[]): void {
  for (const path of paths) {
    try {
      rmSync(path, { force: true })
    } catch {
      /* best effort */
    }
  }
}

function readCaptured(path: string, maxOutput: number): string {
  try {
    return readFileSync(path, 'utf8').slice(0, maxOutput)
  } catch {
    return ''
  }
}

/** Candidate compilers, in the order they are preferred. */
function candidateCompilers(): Toolchain[] {
  const candidates: Toolchain[] = []
  const clangNames = ['clang.exe', 'clang']
  const root = process.env['ProgramFiles'] ?? 'C:\\Program Files'
  const localAppData = process.env['LOCALAPPDATA']
  const clangRoots = [
    join(root, 'LLVM', 'bin'),
    'C:\\msys64\\clang64\\bin',
    'C:\\msys64\\ucrt64\\bin',
    'C:\\msys64\\mingw64\\bin',
    ...(localAppData === undefined ? [] : [join(localAppData, 'Programs', 'LLVM', 'bin')]),
  ]
  for (const base of clangRoots) {
    for (const name of clangNames) {
      candidates.push({
        command: join(base, name),
        label: `clang (${base})`,
        kind: 'clang-lld',
      })
    }
  }
  candidates.push({ command: 'clang', label: 'clang (PATH)', kind: 'clang-lld' })

  // 32-bit-capable cross compilers. The `i686`/`i386` spellings are what a Linux
  // or MSYS2 install exposes for this target; the x86_64 ones can also emit `-m32`
  // when their multilib is present, so they are probed rather than trusted.
  for (const triple of [
    'i686-linux-gnu-gcc',
    'i386-linux-gnu-gcc',
    'i686-pc-linux-gnu-gcc',
    'i686-w64-mingw32-gcc',
    'x86_64-linux-gnu-gcc',
  ]) {
    candidates.push({ command: triple, label: `${triple} (PATH)`, kind: 'cross-gcc', target: triple.replace(/-gcc$/, '') })
  }
  // Plain gcc can target i386 with `-m32` when its multilib is installed, and the
  // probe is what decides — a gcc without multilib simply fails and is skipped.
  candidates.push({ command: 'gcc', label: 'gcc (PATH)', kind: 'gcc-linux' })
  return candidates
}

let cachedToolchain: Toolchain | null | undefined

/**
 * Find a compiler that can actually emit a 32-bit (i386) Linux ELF here.
 *
 * Detection is empirical: a one-function probe is compiled into a scratch
 * directory and its magic bytes are checked, so a compiler that exists but
 * cannot reach a Linux target is rejected instead of failing at challenge build
 * time. An explicit `DSH_REVERSE_TUTOR_CC` is probed first; when it cannot do the
 * job, a candidate that *can* is used and `warnings` says so — silently preferring
 * the auto-detected compiler would hide a misconfiguration, and failing outright
 * would take the lesson down for no reason.
 */
export function detectToolchain(warnings: string[] = []): Toolchain | undefined {
  if (cachedToolchain !== undefined) return cachedToolchain ?? undefined
  let found: Toolchain | undefined
  let candidates: readonly Toolchain[] = []
  let pipesDenied = false

  const explicit = process.env[COMPILER_ENV]
  if (explicit !== undefined && explicit.trim() !== '') {
    const configured: Toolchain = {
      command: explicit.trim(),
      label: `configured (${shortPath(explicit.trim())})`,
      kind: 'clang-lld',
    }
    const probed = probeForToolchain([configured])
    pipesDenied = probed.pipesDenied
    if (probed.found !== undefined) {
      cachedToolchain = probed.found
      return probed.found
    }
    if (!probed.pipesDenied) {
      warnings.push(
        `${COMPILER_ENV} points at ${shortPath(explicit.trim())}, which cannot produce a 32-bit Linux ELF; ` +
          'falling back to an auto-detected compiler',
      )
    }
  }

  const probed = probeForToolchain(candidateCompilers())
  found = probed.found
  candidates = probed.candidates
  pipesDenied = pipesDenied || probed.pipesDenied

  // A host that refuses every pipe also refuses the probe, so detection cannot
  // conclude "no compiler": it can only conclude "cannot run one right now". Take
  // the first candidate that exists on disk rather than downgrading the whole lesson
  // to the emitted artefact, and let the real compile report any genuine failure.
  if (found === undefined && pipesDenied) found = candidates[0]
  cachedToolchain = found ?? null
  return found
}

/** Run the i386 probe against every candidate, in preference order. */
function probeForToolchain(candidates: readonly Toolchain[]): {
  readonly found: Toolchain | undefined
  readonly candidates: readonly Toolchain[]
  readonly pipesDenied: boolean
} {
  const dir = mkdtempSync(join(scratchDir(), 'probe-'))
  const source = join(dir, 'probe.c')
  const output = join(dir, 'probe.elf')
  writeFileSync(source, PROBE_SOURCE, 'utf8')
  let found: Toolchain | undefined
  let pipesDenied = false
  try {
    const usable = candidates.filter(candidate => {
      if (!candidate.command.includes('\\') && !candidate.command.includes('/')) return true
      return existsSync(candidate.command)
    })
    for (const candidate of usable) {
      const args = probeArgs(candidate, source, output)
      const result = runProcessSync(candidate.command, args, dir)
      if (result.pipesDenied) {
        pipesDenied = true
        break
      }
      if (result.status !== 0) continue
      if (!existsSync(output)) continue
      const magic = readFileSync(output).subarray(0, 4)
      if (magic.length === 4 && magic[0] === 0x7f && magic[1] === 0x45 && magic[2] === 0x4c && magic[3] === 0x46) {
        found = candidate
        break
      }
      try {
        rmSync(output, { force: true })
      } catch {
        /* best effort */
      }
    }
    return { found, candidates: usable, pipesDenied }
  } finally {
    try {
      rmSync(dir, { recursive: true, force: true })
    } catch {
      /* best effort */
    }
  }
}

/** Compiler arguments for the i386 ELF probe. */
function probeArgs(toolchain: Toolchain, source: string, output: string): string[] {
  if (toolchain.kind === 'clang-lld') {
    return [
      `--target=${TARGET.triple}`,
      '-m32',
      '-O0',
      '-nostdlib',
      '-static',
      '-fno-asynchronous-unwind-tables',
      '-fno-unwind-tables',
      '-fuse-ld=lld',
      '-Wl,--build-id=none',
      '-Wl,-e,_start',
      '-o',
      output,
      source,
    ]
  }
  if (toolchain.kind === 'cross-gcc') {
    return ['-m32', '-O0', '-nostdlib', '-static', '-Wl,--build-id=none', '-Wl,-e,_start', '-o', output, source]
  }
  return ['-m32', '-O0', '-nostdlib', '-static', '-Wl,--build-id=none', '-Wl,-e,_start', '-o', output, source]
}

/** Synchronous probe runner: detection happens before any tool executes. */
function runProcessSync(
  command: string,
  args: readonly string[],
  cwd: string,
): { readonly status: number | null; readonly pipesDenied: boolean } {
  // Only used for short, fixed probe compiles. `spawnSync` keeps detection
  // deterministic and free of an event-loop dependency. Output goes to files, not
  // pipes, because a confined host may refuse the pipe and make a working compiler
  // look absent.
  const outPath = join(cwd, 'probe.out')
  const errPath = join(cwd, 'probe.err')
  let fdOut: number | undefined
  let fdErr: number | undefined
  let stdio: StdioOptions = 'ignore'
  try {
    fdOut = openSync(outPath, 'w')
    fdErr = openSync(errPath, 'w')
    stdio = ['ignore', fdOut, fdErr]
  } catch {
    safeClose(fdOut, fdErr)
    fdOut = undefined
    fdErr = undefined
  }

  let result
  try {
    result = spawnSync(command, [...args], {
      cwd,
      shell: false,
      timeout: 20_000,
      windowsHide: true,
      env: childEnv(),
      stdio,
    })
  } catch (error) {
    safeClose(fdOut, fdErr)
    return { status: null, pipesDenied: isPipeDenial(error) }
  }
  safeClose(fdOut, fdErr)
  cleanupFiles(outPath, errPath)
  const code = (result.error as { readonly code?: unknown } | undefined)?.code
  return { status: result.status, pipesDenied: code === 'EPERM' || code === 'EACCES' || code === 'ENOTSUP' }
}

/**
 * Build the compile plan for a challenge source.
 *
 * The returned command is a fixed compiler plus a structured argument vector;
 * the only caller-influenced values are the paths this plugin itself computed.
 */
/**
 * Build the compile plan for a challenge source.
 *
 * The returned command is a fixed compiler plus a structured argument vector;
 * the only caller-influenced values are the paths this plugin itself computed.
 *
 * `-m32` is what makes the target 32-bit, and `-march=i386` keeps the generated
 * code inside the baseline instruction set so nothing surprises a student reading
 * it in `ida.exe`.
 */
export function buildCompileCommand(
  toolchain: Toolchain,
  options: {
    readonly sourcePath: string
    readonly outputPath: string
    readonly includeDir: string
    readonly debugInfo: boolean
    /** Linker script that fixes the image at 0x08048000 with `.text` at 0x08049000. */
    readonly linkerScript?: string
  },
): CompileCommand {
  const { sourcePath, outputPath, includeDir, debugInfo, linkerScript } = options
  const common = [
    '-m32',
    '-march=i386',
    '-O0',
    '-std=c11',
    '-nostdlib',
    '-static',
    '-fno-asynchronous-unwind-tables',
    '-fno-unwind-tables',
    '-fno-stack-protector',
    '-fno-pic',
    ...(debugInfo ? ['-g'] : []),
    `-I${includeDir}`,
    '-Wl,--build-id=none',
    '-Wl,-e,_start',
  ]
  const layout = linkerScript === undefined ? [] : [`-Wl,-T,${linkerScript}`]
  if (toolchain.kind === 'clang-lld') {
    return {
      command: toolchain.command,
      label: toolchain.label,
      args: [`--target=${TARGET.triple}`, ...common, ...layout, '-fuse-ld=lld', '-o', outputPath, sourcePath],
    }
  }
  return {
    command: toolchain.command,
    label: toolchain.label,
    args: [...common, ...layout, '-o', outputPath, sourcePath],
  }
}

/** Strip the ELF symbol table in place, when a strip tool is available. */
export function stripCommand(toolchain: Toolchain, binaryPath: string): CompileCommand | undefined {
  const candidates: string[] = []
  if (toolchain.command.includes('\\') || toolchain.command.includes('/')) {
    const base = dirname(toolchain.command)
    candidates.push(join(base, 'llvm-strip.exe'), join(base, 'strip.exe'))
  }
  const root = process.env['ProgramFiles'] ?? 'C:\\Program Files'
  candidates.push(
    join(root, 'LLVM', 'bin', 'llvm-strip.exe'),
    'C:\\msys64\\clang64\\bin\\strip.exe',
    'C:\\msys64\\ucrt64\\bin\\strip.exe',
    'C:\\msys64\\mingw64\\bin\\strip.exe',
  )
  for (const candidate of candidates) {
    if (existsSync(candidate)) {
      return { command: candidate, args: ['--strip-all', binaryPath], label: shortPath(candidate) }
    }
  }
  return undefined
}

/**
 * Locate a real disassembler, preferring the one shipped beside the compiler.
 *
 * A trustworthy listing matters more here than anywhere else in the plugin: a
 * reversed operand is a syntactically valid lie, and this tool feeds a student.
 * So `llvm-objdump`/`objdump` is used whenever the host has one, and the bundled
 * JavaScript decoder in `inspect/x86.ts` is the fallback for hosts that do not.
 *
 * `llvm-objdump` is checked before `objdump` because GNU objdump from an MSYS2
 * mingw-w64 install is a PE-only binutils and fails on an ELF input.
 */
export function detectDisassembler(): CompileCommand | undefined {
  const candidates: string[] = []
  const toolchain = detectToolchain()
  if (toolchain !== undefined && (toolchain.command.includes('\\') || toolchain.command.includes('/'))) {
    const base = dirname(toolchain.command)
    candidates.push(join(base, 'llvm-objdump.exe'), join(base, 'objdump.exe'))
  }
  const root = process.env['ProgramFiles'] ?? 'C:\\Program Files'
  candidates.push(
    join(root, 'LLVM', 'bin', 'llvm-objdump.exe'),
    'C:\\msys64\\clang64\\bin\\llvm-objdump.exe',
    'C:\\msys64\\clang64\\bin\\objdump.exe',
    '/usr/bin/llvm-objdump',
    '/usr/bin/objdump',
  )
  for (const candidate of candidates) {
    if (existsSync(candidate)) {
      return { command: candidate, args: [], label: shortPath(candidate) }
    }
  }
  return undefined
}

const CACHED_RUNTIME = Symbol('reverse-tutor.runtime')

interface RuntimeCache {
  [CACHED_RUNTIME]?: ExecutionRuntime | null
}

const runtimeCache: RuntimeCache = {}

/**
 * Locate a runtime able to execute the built Linux ELF.
 *
 * This is optional on purpose. A Windows host without WSL or `qemu-user` cannot
 * run the binary, and the tutor degrades to the template predicate instead of
 * refusing to verify at all. Detection is cached for the process lifetime.
 */
export function detectRuntime(): ExecutionRuntime | undefined {
  if (runtimeCache[CACHED_RUNTIME] !== undefined) return runtimeCache[CACHED_RUNTIME] ?? undefined

  const configured = process.env[RUNTIME_ENV]
  let found: ExecutionRuntime | undefined
  if (configured !== undefined && configured.trim() !== '') {
    const trimmed = configured.trim()
    if (trimmed === 'wsl' || trimmed === 'wsl.exe') {
      if (wslAvailable()) found = { kind: 'wsl', label: 'WSL', command: 'wsl.exe', prefixArgs: ['-e'] }
    } else {
      found = { kind: isAbsolute(trimmed) ? 'qemu' : 'native', label: trimmed, command: trimmed }
    }
  }

  if (found === undefined && process.platform !== 'win32') {
    found = { kind: 'native', label: 'native Linux' }
  }
  if (found === undefined && process.platform === 'win32') {
    if (wslAvailable()) {
      found = { kind: 'wsl', label: 'WSL', command: 'wsl.exe', prefixArgs: ['-e'] }
    } else {
      const qemu = findQemu()
      if (qemu !== undefined) found = { kind: 'qemu', label: shortPath(qemu), command: qemu }
    }
  }
  if (found === undefined && process.platform !== 'win32') {
    const qemu = findQemu()
    if (qemu !== undefined) found = { kind: 'qemu', label: shortPath(qemu), command: qemu }
  }

  runtimeCache[CACHED_RUNTIME] = found ?? null
  return found
}

function wslAvailable(): boolean {
  if (process.platform !== 'win32') return false
  const result = spawnSync('wsl.exe', ['-e', '/bin/sh', '-c', 'echo ok'], {
    shell: false,
    timeout: 8_000,
    windowsHide: true,
    encoding: 'utf8',
  })
  return result.status === 0 && typeof result.stdout === 'string' && result.stdout.includes('ok')
}

function findQemu(): string | undefined {
  const names = ['qemu-i386.exe', 'qemu-i386', 'qemu-x86_64.exe', 'qemu-x86_64']
  const roots = [
    process.env['ProgramFiles'] ?? 'C:\\Program Files',
    'C:\\msys64\\mingw64\\bin',
    'C:\\msys64\\ucrt64\\bin',
    'C:\\msys64\\clang64\\bin',
    'C:\\msys64\\usr\\bin',
  ]
  for (const root of roots) {
    for (const name of names) {
      const candidate = join(root, 'qemu', name)
      if (existsSync(candidate)) return candidate
      const flat = join(root, name)
      if (existsSync(flat)) return flat
    }
  }
  return undefined
}

/** Clear detection caches; used by tests. */
export function resetToolchainCache(): void {
  cachedToolchain = undefined
  runtimeCache[CACHED_RUNTIME] = undefined
}

/** Create a fresh, uniquely named scratch directory. */
export function makeScratch(prefix = 'build-'): string {
  return mkdtempSync(join(scratchDir(), prefix))
}
