/**
 * `reverse_inspect` — bounded, factual observation of a challenge.
 *
 * The tool answers observation questions and never interpretation ones. Five
 * actions are supported, and each is bounded in three ways: by a wall-clock
 * timeout, by a character budget, and by being scoped to one challenge
 * workspace. The `objdump` action resolves a *function*, not a section, because
 * handing the model a whole `.text` is both expensive and unhelpful.
 *
 * `ida_context` is the bridge to the student's own IDA Pro session: it reads the
 * JSON that the shipped IDAPython script exports, so the tutor can ask about the
 * function the student is actually looking at.
 *
 * @module dsh-reverse-tutor/tools/reverse-inspect
 */

import { existsSync, statSync } from 'node:fs'
import { clampText, DEFAULT_LIMITS, readJson } from '../policy.js'
import { challengePaths, readVaultEntry } from '../challenge/workspace.js'
import { runProcess, detectDisassembler } from '../challenge/toolchain.js'
import { parseElf, renderFileView, renderReadelfView, renderStringsView } from '../inspect/elf.js'
import { listFunctions, renderObjdump, renderWithSystemDisassembler } from '../inspect/objdump.js'
import { outputSchemaPair, compileParameterSpec } from './schema.js'
import type { AuthorSchema } from './schema.js'
import type { ToolTextBlock } from './render.js'

/** The observation actions `reverse_inspect` supports. */
export type InspectAction = 'file' | 'strings' | 'readelf' | 'objdump' | 'ida_context' | 'bridge'

/** Arguments accepted by `reverse_inspect`. */
export interface ReverseInspectArgs {
  readonly challengeId: string
  readonly action: InspectAction
  readonly functionName?: string
  readonly minLength?: number
}

/** The structured value returned to the model. */
export interface ReverseInspectValue {
  readonly ok: boolean
  readonly action: string
  readonly challengeId: string
  readonly source: string
  /** Output kind so the presentation layer can pick a code card. */
  readonly kind: 'text' | 'json' | 'error'
  readonly text: string
  readonly truncated: boolean
  /** Extra facts derived while producing the output. */
  readonly facts: Readonly<Record<string, unknown>>
  readonly nextSteps: readonly string[]
}

/** Parameter schema. */
export const reverseInspectParameters = {
  challengeId: {
    type: 'string' as const,
    required: true as const,
    description: 'Challenge id returned by reverse_build.',
  },
  action: {
    type: 'string' as const,
    required: true as const,
    enum: ['file', 'strings', 'readelf', 'objdump', 'ida_context', 'bridge'] as const,
    description:
      '`file` = format summary; `strings` = printable runs with offsets; `readelf` = section and program headers; ' +
      '`objdump` = instruction listing for one function; `ida_context` = the JSON exported from the student\'s IDA Pro session; ' +
      '`bridge` = the exact steps and paths the student needs to export that JSON.',
  },
  functionName: {
    type: 'string' as const,
    description:
      'For `objdump`: a symbol name, `entry`, or an address such as `0x08049000` / `sub_8049000`. Delivered challenges are stripped, so an address is usually the only anchor — the output lists the ones that exist.',
  },
  minLength: {
    type: 'integer' as const,
    description: 'For `strings`: minimum run length. Defaults to 4, the usual `strings(1)` threshold.',
  },
}

/** Output schema, compiled by {@link objectSchema}. */
const reverseInspectOutputSchemaFields = {
  ok: { type: 'boolean', required: true, description: 'Whether the observation succeeded.' },
  action: { type: 'string', required: true, description: 'The action that produced this result.' },
  challengeId: { type: 'string', required: true, description: 'Challenge that was inspected.' },
  source: { type: 'string', required: true, description: 'Which mechanism produced the output.' },
  kind: {
    type: 'string',
    required: true,
    enum: ['text', 'json', 'error'],
    description: 'Output kind, so the renderer can pick a card.',
  },
  text: { type: 'string', required: true, description: 'The observation itself.' },
  truncated: { type: 'boolean', required: true, description: 'Whether the character budget cut the output.' },
  facts: { type: 'json', required: true, description: 'Structured facts derived while producing the output.' },
  nextSteps: {
    type: 'array',
    required: true,
    description: 'Questions worth asking next.',
    items: { type: 'string' },
  },
} satisfies Record<string, AuthorSchema>

/** One description, two projections: `author` for `defineTool`, `raw` for the registry. */
export const { author: reverseInspectOutputAuthorSchema, raw: reverseInspectOutputSchema } =
  outputSchemaPair(reverseInspectOutputSchemaFields)

/**
 * The compiled projections `ctx.tools.register` validates.
 *
 * `register` checks `parameters` and `output.schema` as raw JSON Schema before
 * inserting the definition, so neither can be the author-facing form here.
 */
export const reverseInspectCompiledOutputSchema = reverseInspectOutputSchema
export const reverseInspectParametersCompiled = compileParameterSpec(reverseInspectParameters)

/** Render an inspection result for the model. */
export function renderReverseInspect(_args: ReverseInspectArgs, value: ReverseInspectValue): readonly ToolTextBlock[] {
  const header = `reverse_inspect(${value.action}) for ${value.challengeId} — source: ${value.source}`
  return [{ type: 'text', text: `${header}\n\n${value.text}` }]
}

/** Input shape of the IDA bridge JSON. */
interface IdaContext {
  readonly binary?: { readonly name?: string; readonly architecture?: string; readonly path?: string }
  readonly schema?: string
  readonly cursor?: { readonly address?: string; readonly function?: string }
  readonly currentFunction?: { readonly name?: string; readonly start?: string; readonly end?: string }
  readonly assembly?: readonly { readonly address?: string; readonly text?: string }[]
  readonly pseudocode?: string | null
  readonly callers?: readonly string[]
  readonly callees?: readonly string[]
  readonly strings?: readonly string[]
  readonly comments?: readonly { readonly address?: string; readonly text?: string }[]
  readonly decompilerAvailable?: boolean
}

/** Execute one `reverse_inspect` call. */
export async function executeReverseInspect(args: ReverseInspectArgs): Promise<ReverseInspectValue> {
  const challengeId = typeof args.challengeId === 'string' ? args.challengeId : ''
  let paths
  try {
    paths = challengePaths(challengeId)
  } catch (error) {
    return failure(challengeId, args.action, error instanceof Error ? error.message : String(error))
  }

  const entry = readVaultEntry(challengeId)
  if (entry === undefined) {
    return failure(
      challengeId,
      args.action,
      `unknown challengeId "${challengeId}"; call reverse_build first, and use the id it returned`,
    )
  }
  if (!existsSync(paths.binaryPath)) {
    return failure(challengeId, args.action, `the binary for ${challengeId} is missing from its workspace`)
  }

  switch (args.action) {
    case 'file':
      return inspectFile(challengeId, paths.binaryPath)
    case 'strings':
      return inspectStrings(challengeId, paths.binaryPath, args.minLength)
    case 'readelf':
      return inspectReadelf(challengeId, paths.binaryPath)
    case 'objdump':
      return inspectObjdump(challengeId, paths.binaryPath, args.functionName)
    case 'ida_context':
      return inspectIdaContext(challengeId, paths.contextPath)
    case 'bridge':
      return bridgeInstructions(challengeId, paths.binaryPath, paths.contextPath)
    default:
      return failure(
        challengeId,
        String(args.action),
        `unsupported action "${String(args.action)}"; use file, strings, readelf, objdump, ida_context or bridge`,
      )
  }
}

function failure(challengeId: string, action: string, text: string): ReverseInspectValue {
  return {
    ok: false,
    action: String(action),
    challengeId,
    source: 'none',
    kind: 'error',
    text,
    truncated: false,
    facts: {},
    nextSteps: ['Report the failure as-is; do not guess at what the binary contains.'],
  }
}

function describeInfo(path: string): ReturnType<typeof parseElf> {
  return parseElf(path)
}

function inspectFile(challengeId: string, binaryPath: string): ReverseInspectValue {
  const info = describeInfo(binaryPath)
  const functions = listFunctions(info)
  const facts = {
    class: info.className,
    type: info.typeName,
    machine: info.machineName,
    // Surfaced so the tutor can tell immediately that this is the 32-bit target
    // the student's IDA build can open.
    opensInIda32: info.isTarget,
    entry: `0x${info.entry.toString(16)}`,
    segments: info.segments.length,
    sections: info.sections.length,
    symbols: info.symbols.length,
    size: info.size,
    functions: functions.map(entry => `${entry.name}@0x${entry.address.toString(16)}`),
  }
  const text = clampText(
    [
      renderFileView(info),
      '',
      'analysis anchors:',
      ...functions.map(entry => `  ${entry.name} @ 0x${entry.address.toString(16)}`),
      '',
      'this is observation only: it says what the file is, not what it does.',
    ].join('\n'),
    DEFAULT_LIMITS.maxOutputChars,
  )
  return {
    ok: true,
    action: 'file',
    challengeId,
    source: 'computed from the ELF header',
    kind: 'text',
    text,
    truncated: text.length >= DEFAULT_LIMITS.maxOutputChars,
    facts,
    nextSteps: [
      'Ask the student what the absence of a dynamic interpreter implies about how the program talks to the kernel.',
      'Ask which section the reference data most likely lives in, and how they would confirm it.',
    ],
  }
}

async function inspectStrings(
  challengeId: string,
  binaryPath: string,
  minLength: number | undefined,
): Promise<ReverseInspectValue> {
  const minimum = Number.isFinite(minLength) ? Math.max(4, Math.trunc(minLength as number)) : 4
  // The computed view is always available and always reports file offsets, so it
  // is the baseline. A system `strings` is consulted only when it produces a
  // richer answer, and its output is put in the same shape so the tutor sees one
  // format regardless of host.
  const computed = renderStringsView(binaryPath, { minLength: minimum, maxCount: 240 })
  const native = await runStrings(binaryPath, minimum)
  const text = clampText(native ?? computed, DEFAULT_LIMITS.maxOutputChars)
  return {
    ok: true,
    action: 'strings',
    challengeId,
    source: native === undefined ? 'computed from the file bytes' : 'system strings tool',
    kind: 'text',
    text,
    truncated: text.length >= DEFAULT_LIMITS.maxOutputChars,
    facts: { minLength: minimum },
    nextSteps: [
      'Ask the student which string belongs to the prompt and which could be a program name or a message.',
      'The reference data for a numeric transform is not printable, so it will not appear here — ask the student what that implies.',
    ],
  }
}

/**
 * Use a system `strings`, when the host has one.
 *
 * The output is re-rendered with file offsets so this action's shape does not
 * depend on which implementation answered. A tool that fails, times out, or
 * returns nothing yields `undefined` and the computed view is used instead.
 */
async function runStrings(binaryPath: string, minLength: number): Promise<string | undefined> {
  const known = process.platform === 'win32'
    ? [
        'C:\\msys64\\clang64\\bin\\strings.exe',
        'C:\\msys64\\ucrt64\\bin\\strings.exe',
        'C:\\msys64\\mingw64\\bin\\strings.exe',
        'C:\\msys64\\usr\\bin\\strings.exe',
      ]
    : ['/usr/bin/strings', '/bin/strings']
  const available = known.find(path => existsSync(path))
  if (available === undefined) return undefined
  const result = await runProcess(available, ['-t', 'x', '-n', String(minLength), binaryPath], {
    timeoutMs: DEFAULT_LIMITS.inspectTimeoutMs,
    maxOutputChars: DEFAULT_LIMITS.maxOutputChars * 2,
  })
  if (result.timedOut || result.spawnError !== undefined || result.code !== 0) return undefined
  const lines: string[] = []
  const seen = new Set<string>()
  for (const line of result.stdout.split(/\r?\n/)) {
    // `strings -t x` emits `<hex offset> <text>`; keep that pairing and drop the
    // duplicates the challenge's repeated banner would otherwise produce.
    const match = /^\s*([0-9a-f]+)\s+(.+)$/.exec(line)
    if (match === null) continue
    const text = match[2]!.trimEnd()
    if (text.length < minLength || seen.has(text)) continue
    seen.add(text)
    lines.push(`0x${match[1]!.padStart(6, '0')}  ${text}`)
  }
  return lines.length === 0 ? undefined : lines.join('\n')
}

function inspectReadelf(challengeId: string, binaryPath: string): ReverseInspectValue {
  const info = describeInfo(binaryPath)
  const text = clampText(renderReadelfView(info, { limit: 32 }), DEFAULT_LIMITS.maxOutputChars)
  const facts = {
    type: info.typeName,
    entry: `0x${info.entry.toString(16)}`,
    segments: info.segments.map(segment => ({
      type: segment.type,
      vaddr: `0x${segment.vaddr.toString(16)}`,
      fileSize: segment.fileSize,
      flags: segment.flags,
    })),
    sections: info.sections.map(section => ({
      name: section.name,
      address: `0x${section.address.toString(16)}`,
      size: section.size,
    })),
  }
  return {
    ok: true,
    action: 'readelf',
    challengeId,
    source: 'computed from the ELF header',
    kind: 'text',
    text,
    truncated: text.length >= DEFAULT_LIMITS.maxOutputChars,
    facts,
    nextSteps: [
      'Ask the student to name the virtual address range the executable segment covers and which section sits inside it.',
      'Ask what the absence of a `.symtab` entry means for how they will refer to functions.',
    ],
  }
}

async function inspectObjdump(
  challengeId: string,
  binaryPath: string,
  functionName: string | undefined,
): Promise<ReverseInspectValue> {
  const info = describeInfo(binaryPath)
  let rendered: ReturnType<typeof renderObjdump>
  try {
    rendered = renderObjdump(info, functionName, { maxInstructions: 180 })
  } catch (error) {
    const anchors = listFunctions(info)
      .map(entry => `${entry.name} @ 0x${entry.address.toString(16)}`)
      .join(', ')
    return {
      ok: false,
      action: 'objdump',
      challengeId,
      source: 'computed disassembly',
      kind: 'error',
      text: `${error instanceof Error ? error.message : String(error)}\navailable anchors: ${anchors}`,
      truncated: false,
      facts: {},
      nextSteps: [
        'Ask the student to tell you the address of the function IDA is showing (the export script reports it).',
        'Retry with that address.',
      ],
    }
  }

  // Prefer the host's own disassembler: it is the reference implementation, and a
  // reversed operand here would teach a student something false.
  const disassembler = detectDisassembler()
  let text: string | undefined
  let source = 'computed disassembly (verify anything decisive in the student\'s IDA Pro)'
  if (disassembler !== undefined) {
    text = await renderWithSystemDisassembler(
      info,
      rendered.block,
      disassembler,
      DEFAULT_LIMITS.inspectTimeoutMs,
      DEFAULT_LIMITS.maxOutputChars * 2,
    )
    if (text !== undefined) source = `${disassembler.label} (Intel syntax)`
  }
  if (text === undefined) text = rendered.text
  text = clampText(text, DEFAULT_LIMITS.maxOutputChars)

  return {
    ok: true,
    action: 'objdump',
    challengeId,
    source,
    kind: 'text',
    text,
    truncated: text.length >= DEFAULT_LIMITS.maxOutputChars,
    facts: {
      function: rendered.block.name,
      address: `0x${rendered.block.address.toString(16)}`,
      instructions: rendered.block.instructions.length,
      calls: rendered.block.calls.map(target => `0x${target.toString(16)}`),
      dataReferences: rendered.block.dataReferences.map(target => `0x${target.toString(16)}`),
      disassembler: disassembler?.label ?? 'bundled decoder',
    },
    nextSteps: [
      'Ask the student to point at the instruction that transforms the input byte, and to say which register holds the input.',
      'Where the pseudocode and this listing disagree, ask the student to trust the assembly and explain the difference.',
    ],
  }
}

function inspectIdaContext(challengeId: string, contextPath: string): ReverseInspectValue {
  if (!existsSync(contextPath)) {
    return {
      ok: false,
      action: 'ida_context',
      challengeId,
      source: 'none',
      kind: 'error',
      text:
        `no IDA context has been exported for ${challengeId} yet (expected at ${contextPath}).\n` +
        'Ask the student to open the binary in IDA Pro, put the cursor inside the function they want to discuss, ' +
        'and run the Reverse Tutor export script — call reverse_inspect with action "bridge" for the exact steps.',
      truncated: false,
      facts: {},
      nextSteps: ['Ask the student for the exact steps they ran in IDA, rather than guessing why the export is missing.'],
    }
  }

  const raw = readJson<IdaContext>(contextPath)
  if (raw === undefined) {
    return {
      ok: false,
      action: 'ida_context',
      challengeId,
      source: 'ida_context.json (unparseable)',
      kind: 'error',
      text: 'the exported IDA context is not valid JSON; ask the student to run the export script again.',
      truncated: false,
      facts: {},
      nextSteps: ['Ask the student to re-run the export and report any error IDA printed.'],
    }
  }

  const age = Date.now() - statSync(contextPath).mtimeMs
  const lines: string[] = []
  lines.push(`exported from IDA Pro`)
  if (raw.binary !== undefined) {
    lines.push(`binary: ${raw.binary.name ?? '(unnamed)'}  architecture: ${raw.binary.architecture ?? '(unknown)'}`)
  }
  if (raw.cursor?.address !== undefined) lines.push(`cursor: ${raw.cursor.address}`)
  if (raw.currentFunction !== undefined) {
    lines.push(
      `current function: ${raw.currentFunction.name ?? '(unnamed)'} ` +
        `${raw.currentFunction.start ?? '?'}..${raw.currentFunction.end ?? '?'}`,
    )
  }
  if (raw.decompilerAvailable === false) {
    lines.push('hex-rays decompiler: not available in this IDA install (pseudocode omitted)')
  }
  if (raw.callers !== undefined && raw.callers.length > 0) lines.push(`callers: ${raw.callers.join(', ')}`)
  if (raw.callees !== undefined && raw.callees.length > 0) lines.push(`callees: ${raw.callees.join(', ')}`)
  if (raw.strings !== undefined && raw.strings.length > 0) {
    lines.push(`strings referenced here: ${raw.strings.slice(0, 20).join(' | ')}`)
  }

  if (raw.assembly !== undefined && raw.assembly.length > 0) {
    lines.push('', `assembly (${raw.assembly.length} instructions):`)
    for (const instruction of raw.assembly.slice(0, 160)) {
      lines.push(`  ${instruction.address ?? '?'}  ${instruction.text ?? ''}`)
    }
    if (raw.assembly.length > 160) lines.push(`  ... ${raw.assembly.length - 160} more instructions omitted`)
  }

  if (typeof raw.pseudocode === 'string' && raw.pseudocode.trim().length > 0) {
    lines.push('', 'pseudocode (Hex-Rays output — an analysis artefact, not ground truth):')
    lines.push(raw.pseudocode.trim())
  } else {
    lines.push('', 'pseudocode: (not exported)')
  }

  const text = clampText(lines.join('\n'), DEFAULT_LIMITS.maxOutputChars)
  return {
    ok: true,
    action: 'ida_context',
    challengeId,
    source: `student's IDA Pro session (exported ${Math.round(age / 1000)}s ago)`,
    kind: 'text',
    text,
    truncated: text.length >= DEFAULT_LIMITS.maxOutputChars,
    facts: {
      cursor: raw.cursor?.address ?? null,
      function: raw.currentFunction?.name ?? null,
      instructionCount: raw.assembly?.length ?? 0,
      hasPseudocode: typeof raw.pseudocode === 'string' && raw.pseudocode.length > 0,
      callers: raw.callers ?? [],
      callees: raw.callees ?? [],
    },
    nextSteps: [
      'Ask about the function the student is actually looking at — do not redirect them to a different one without a reason.',
      'Ask which instruction produces the value that eventually reaches the comparison.',
      'If the pseudocode is ambiguous, ask the student to check the assembly for the same operation.',
    ],
  }
}

function bridgeInstructions(challengeId: string, binaryPath: string, contextPath: string): ReverseInspectValue {
  const script = process.env['DSH_REVERSE_TUTOR_IDA_SCRIPT'] ?? '(see the package\'s ida/ directory)'
  const text = [
    `To export the IDA context for ${challengeId}:`,
    '',
    '1. Open this file in IDA Pro (File > Open):',
    `   ${binaryPath}`,
    '   Accept the default loader settings. Let auto-analysis finish.',
    '',
    '2. Put the cursor inside the function you want to discuss.',
    '',
    '3. In IDA, run the shipped export script. Either:',
    `   - File > Script file... and choose: ${script}`,
    '   - or paste this into the IDA Python console (the bottom input line):',
    `     exec(open(r"${script}").read())`,
    '',
    '4. The script writes the context here:',
    `   ${contextPath}`,
    '',
    '5. Tell your tutor that the export is done; the tutor then reads it.',
    '',
    'Notes:',
    '- The export contains only what IDA already knows about the function under the cursor:',
    '  its name, boundaries, disassembly, and pseudocode when Hex-Rays is present.',
    '- It writes to one path, never reads anything else, and never touches the network.',
    `- If the script path is not configured, the file ships inside the plugin package at ida/reverse_tutor_export.py.`,
  ].join('\n')
  return {
    ok: true,
    action: 'bridge',
    challengeId,
    source: 'static instructions',
    kind: 'text',
    text,
    truncated: false,
    facts: { binaryPath, contextPath, script },
    nextSteps: [
      'Wait for the student to confirm the export before calling reverse_inspect("ida_context").',
    ],
  }
}
