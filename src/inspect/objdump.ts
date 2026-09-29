/**
 * Function-aware disassembly views over an ELF binary.
 *
 * `reverse_inspect("objdump")` must never hand a whole `.text` to the model — a
 * real `objdump -d` on a simple challenge is already hundreds of lines, and on a
 * larger binary it is hundreds of thousands. So this module always resolves a
 * *function*, either by name (from a symbol table when the binary has one) or by
 * the address the caller supplied, and it labels the control flow inside it.
 *
 * Symbols are gone in a delivered challenge (the build strips them), which is the
 * point of the exercise: without names, the student has to find the function by
 * behaviour. The `entry` pseudo-function is always available because the ELF
 * header names it.
 *
 * @module dsh-reverse-tutor/inspect/objdump
 */

import { readFileSync } from 'node:fs'
import type { ElfInfo } from './elf.js'
import { addressToOffset, parseElf, stringAtAddress } from './elf.js'
import { decodeInstruction, formatInstruction } from './x86.js'
import type { Instruction } from './x86.js'
import { runProcess } from '../challenge/toolchain.js'

/** One recovery unit inside the executable image. */
export interface FunctionBlock {
  readonly name: string
  readonly address: number
  readonly bytes: number
  readonly kind: 'entry' | 'symbol' | 'requested'
  readonly instructions: readonly Instruction[]
  /** Direct call targets found inside the block. */
  readonly calls: readonly number[]
  /** RIP-relative data addresses referenced inside the block. */
  readonly dataReferences: readonly number[]
}

/** Locate an executable region and read it. */
export function executableRegions(info: ElfInfo): { address: number; offset: number; size: number }[] {
  return info.segments
    .filter(segment => segment.type === 1 && (segment.flags & 1) !== 0)
    .map(segment => ({ address: segment.vaddr, offset: segment.offset, size: segment.fileSize }))
}

/** Read `size` bytes from a virtual address. */
function bytesAt(info: ElfInfo, address: number, size: number): Buffer | undefined {
  const offset = addressToOffset(info, address)
  if (offset === undefined) return undefined
  const all = readFileSync(info.path)
  if (offset >= all.length) return undefined
  return all.subarray(offset, Math.min(all.length, offset + size))
}

/**
 * Decode one function starting at `address`.
 *
 * Decoding stops at the first `ret`/`hlt`, at an unconditional `jmp`, or when the
 * declared symbol size is consumed — whichever comes first. Following a `jmp`
 * would mean choosing a successor branch, and guessing which one is the function
 * would be worse than stopping.
 */
export function decodeFunction(
  info: ElfInfo,
  address: number,
  options: { readonly name?: string; readonly size?: number; readonly kind?: FunctionBlock['kind']; readonly maxInstructions?: number } = {},
): FunctionBlock {
  const maxInstructions = options.maxInstructions ?? 220
  const declaredSize = options.size !== undefined && options.size > 0 ? options.size : undefined
  const region = executableRegions(info).find(
    entry => address >= entry.address && address < entry.address + entry.size,
  )
  const available = region === undefined ? 512 : Math.min(region.address + region.size - address, 4096)
  const size = Math.min(declaredSize ?? available, available)
  const raw = bytesAt(info, address, size)
  if (raw === undefined || raw.length === 0) {
    return {
      name: options.name ?? `sub_${address.toString(16)}`,
      address,
      bytes: 0,
      kind: options.kind ?? 'requested',
      instructions: [],
      calls: [],
      dataReferences: [],
    }
  }

  const instructions = decodeBlockWithJmpStop(raw, address, maxInstructions, declaredSize)
  const calls: number[] = []
  const dataReferences: number[] = []
  for (const instruction of instructions) {
    const mnemonic = instruction.mnemonic.replace(/^(lock |rep |repne )/, '')
    if (mnemonic === 'call') {
      const match = /^0x([0-9a-f]+)$/.exec(instruction.operands.trim())
      if (match !== null) calls.push(Number.parseInt(match[1]!, 16))
    } else if (mnemonic === 'lea' || mnemonic === 'mov' || mnemonic === 'movzx' || mnemonic === 'cmp') {
      const match = /\[rip([+-]0x[0-9a-f]+)\]/.exec(instruction.operands)
      if (match !== null) {
        const delta = Number.parseInt(match[1]!.replace('+', '').replace('-', ''), 16)
        const target = instruction.address + instruction.length + (match[1]!.startsWith('-') ? -delta : delta)
        dataReferences.push(target)
      }
    }
  }

  const consumed = instructions.reduce((total, instruction) => total + instruction.length, 0)
  return {
    name: options.name ?? `sub_${address.toString(16)}`,
    address,
    bytes: consumed,
    kind: options.kind ?? 'requested',
    instructions,
    calls: [...new Set(calls)],
    dataReferences: [...new Set(dataReferences)],
  }
}

function decodeBlockWithJmpStop(
  raw: Buffer,
  address: number,
  maxInstructions: number,
  declaredSize: number | undefined,
): Instruction[] {
  const out: Instruction[] = []
  let offset = 0
  while (offset < raw.length && out.length < maxInstructions) {
    // `decodeInstruction` reads from the start of the buffer it is given, so the
    // remaining bytes must be handed over as a view and the address adjusted —
    // passing the whole buffer with an offset address would re-decode the first
    // instruction forever.
    const instruction = decodeInstruction(raw.subarray(offset), address + offset)
    out.push(instruction)
    offset += instruction.length
    if (declaredSize !== undefined && offset >= declaredSize) break
    const mnemonic = instruction.mnemonic.replace(/^(lock |rep |repne )/, '')
    if (mnemonic === 'ret' || mnemonic === 'hlt') break
    if (mnemonic === 'jmp') break
    if (mnemonic === 'db') break
  }
  return out
}

/**
 * The functions worth offering for a challenge binary.
 *
 * `entry` always exists. Named symbols are added when the binary carries a
 * symbol table (a build with debug info, or a `-g` build the tutor chose not to
 * strip). Everything else must be reached through the call graph, which is the
 * student's job in IDA.
 */
export function listFunctions(info: ElfInfo): { name: string; address: number; size: number }[] {
  const out: { name: string; address: number; size: number }[] = [
    { name: 'entry', address: info.entry, size: 0 },
  ]
  const named = info.symbols
    .filter(symbol => symbol.type === 'FUNC' && symbol.value !== 0 && symbol.name !== '')
    .map(symbol => ({ name: symbol.name, address: symbol.value, size: symbol.size }))
  for (const symbol of named) {
    if (out.some(entry => entry.address === symbol.address)) continue
    out.push(symbol)
  }
  return out.sort((left, right) => left.address - right.address)
}

/** Resolve a caller-supplied function selector to an address. */
export function resolveFunction(
  info: ElfInfo,
  selector: string | undefined,
): { name: string; address: number; size?: number; kind: FunctionBlock['kind'] } | undefined {
  const wanted = (selector ?? '').trim()
  if (wanted === '' || wanted === 'entry' || wanted === '_start') {
    return { name: wanted === '' ? 'entry' : wanted, address: info.entry, kind: 'entry' }
  }
  if (/^0x[0-9a-f]+$/i.test(wanted)) {
    const address = Number.parseInt(wanted.slice(2), 16)
    const symbol = info.symbols.find(entry => entry.value === address && entry.type === 'FUNC')
    return {
      name: symbol?.name ?? `sub_${address.toString(16)}`,
      address,
      ...(symbol === undefined ? {} : { size: symbol.size }),
      kind: 'requested',
    }
  }
  if (/^\d+$/.test(wanted)) {
    const address = Number.parseInt(wanted, 10)
    return { name: `sub_${address.toString(16)}`, address, kind: 'requested' }
  }
  const symbol = info.symbols.find(entry => entry.name === wanted && entry.type === 'FUNC')
  if (symbol !== undefined) {
    return { name: symbol.name, address: symbol.value, size: symbol.size, kind: 'symbol' }
  }
  // Accept `sub_401000` even when the symbol table was stripped: the address is
  // in the name, which is exactly how a student refers to it in IDA.
  const sub = /^sub_([0-9a-f]+)$/i.exec(wanted)
  if (sub !== null) {
    const address = Number.parseInt(sub[1]!, 16)
    return { name: wanted, address, kind: 'requested' }
  }
  return undefined
}

/** Render an `objdump -d -Mintel`-shaped listing for one function. */
export function renderObjdump(
  info: ElfInfo,
  selector: string | undefined,
  options: { readonly maxInstructions?: number } = {},
): { text: string; block: FunctionBlock } {
  const resolved = resolveFunction(info, selector)
  if (resolved === undefined) {
    const available = listFunctions(info).map(entry => `${entry.name}@0x${entry.address.toString(16)}`).join(', ')
    throw new Error(
      `no function matches "${selector}"; this binary is stripped, so pass an address such as 0x${info.entry.toString(16)} ` +
        `(entry point) — known anchors: ${available || '(none)'}`,
    )
  }
  const block = decodeFunction(info, resolved.address, {
    name: resolved.name,
    kind: resolved.kind,
    ...(resolved.size === undefined ? {} : { size: resolved.size }),
    ...(options.maxInstructions === undefined ? {} : { maxInstructions: options.maxInstructions }),
  })

  const lines: string[] = []
  lines.push(`${info.path}:     file format elf32-i386`)
  lines.push('')
  lines.push(`Disassembly of function ${block.name} (${block.bytes} bytes, ${block.instructions.length} instructions):`)
  lines.push('')
  if (block.instructions.length === 0) {
    lines.push('  no decodable instructions at this address')
  }
  for (const instruction of block.instructions) {
    lines.push(`${formatInstruction(instruction)}   ${annotateDataReference(info, instruction)}`.trimEnd())
  }
  lines.push('')
  if (block.calls.length > 0) {
    lines.push(`direct calls: ${block.calls.map(target => describeTarget(info, target)).join(', ')}`)
  } else {
    lines.push('direct calls: (none)')
  }
  if (block.dataReferences.length > 0) {
    const described = block.dataReferences.map(target => describeTarget(info, target))
    lines.push(`RIP-relative data references: ${described.join(', ')}`)
  }
  return { text: lines.join('\n'), block }
}

/**
 * Produce a listing using the host's own disassembler, when one exists.
 *
 * The external tool is preferred over the bundled decoder because it is the
 * reference implementation; the decoder only runs where no tool is available.
 * The listing is bounded by `--start-address` / `--stop-address`, so even a large
 * `.text` cannot flood the model's context.
 */
export async function renderWithSystemDisassembler(
  info: ElfInfo,
  block: FunctionBlock,
  tool: { readonly command: string; readonly label: string },
  timeoutMs: number,
  maxOutputChars: number,
): Promise<string | undefined> {
  // Stop at the end of the guessed function. Without symbols this is the first
  // `ret`, `hlt`, or `jmp` the decoder found, plus the last instruction's length:
  // a bounded window around the address the caller asked about.
  const last = block.instructions[block.instructions.length - 1]
  const stop = last === undefined ? block.address + 256 : last.address + last.length
  const args = [
    '--disassemble',
    '--x86-asm-syntax=intel',
    `--start-address=0x${block.address.toString(16)}`,
    `--stop-address=0x${stop.toString(16)}`,
    info.path,
  ]
  const result = await runProcess(tool.command, args, { timeoutMs, maxOutputChars })
  if (result.code !== 0 || result.timedOut || result.stdout.trim().length === 0) return undefined

  // Keep the header line naming the tool, then only the instruction lines that
  // fall inside the window, annotated with any string each operand points at.
  const kept: string[] = [
    `${info.path}:     file format elf32-i386`,
    '',
    `Verified listing from ${tool.label} (Intel syntax), function ${block.name} at 0x${block.address.toString(16)}:`,
    '',
  ]
  for (const line of result.stdout.split(/\r?\n/)) {
    if (!/^\s*[0-9a-f]+:/.test(line)) continue
    kept.push(annotateExternalLine(info, line))
  }
  kept.push('')
  kept.push('Cross-check this against IDA Pro: the student\'s database is the reference for their own reasoning.')
  return kept.join('\n')
}

/** Append the string a `movabs`/`lea` operand points at, when it points at one. */
function annotateExternalLine(info: ElfInfo, line: string): string {
  for (const match of line.matchAll(/0x([0-9a-f]{4,})/g)) {
    const address = Number.parseInt(match[1]!, 16)
    // Skip the leading instruction address column.
    if (`0x${address.toString(16)}` === line.trim().split(':')[0]?.trim()) continue
    const text = stringAtAddress(info, address, 48)
    if (text !== undefined && text.length >= 4 && /^[\x20-\x7e]+$/.test(text)) {
      return `${line}   ; "${text}"`
    }
  }
  return line
}

/** Append a trailing comment naming a string constant referenced by the instruction. */
function annotateDataReference(info: ElfInfo, instruction: Instruction): string {
  // Challenge programs load data addresses with `movabs`/`mov r64, imm64`; the
  // first large immediate in the operand text is that address. Annotating it
  // turns "0x402010" into `0x402010 ("Enter the accepted value: ")`, which is
  // the single most useful label an inspection can add.
  let best = ''
  for (const match of instruction.operands.matchAll(/0x([0-9a-f]{4,})/g)) {
    const address = Number.parseInt(match[1]!, 16)
    const text = stringAtAddress(info, address, 48)
    if (text === undefined || text.length < 4) continue
    if (!/^[\x20-\x7e]+$/.test(text)) continue
    best = `; "${text}"`
    break
  }
  return best
}

/** Describe a call or data target: symbol name when known, else the raw address. */
export function describeTarget(info: ElfInfo, address: number): string {
  const symbol = info.symbols.find(entry => entry.value === address && entry.name !== '')
  if (symbol !== undefined) return `${symbol.name}@0x${address.toString(16)}`
  const text = stringAtAddress(info, address, 40)
  if (text !== undefined && text.length >= 4 && /^[\x20-\x7e]+$/.test(text)) {
    return `0x${address.toString(16)} ("${text}")`
  }
  return `0x${address.toString(16)}`
}

/** Parse once and resolve everything the inspector needs. */
export function inspectBinary(path: string): ElfInfo {
  return parseElf(path)
}
