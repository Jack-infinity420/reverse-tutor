/**
 * A dependency-free ELF reader plus the `file` / `strings` / `readelf` views.
 *
 * **The target is 32-bit.** The audience practises x86 32-bit reverse engineering
 * in IDA's 32-bit build, so every challenge this plugin emits is
 * `ELFCLASS32 / EM_386`. The reader is written for that shape — 52-byte ELF
 * header, 32-byte program headers, 40-byte section headers, 4-byte addresses — and
 * it reports the class it actually found rather than assuming one.
 *
 * It refuses rather than guesses: an image whose class or byte order this reader
 * does not implement produces an explicit error instead of a plausible misreading,
 * because a wrong offset silently reported as fact would mislead the student it is
 * meant to help.
 *
 * Native binutils are used when the host has them, because a student's own tooling
 * should stay the reference, but every view has a pure-JavaScript implementation as
 * well. That is what makes `reverse_inspect` work identically on Windows, on a host
 * without binutils, and inside a sandbox that forbids child processes.
 *
 * @module dsh-reverse-tutor/inspect/elf
 */

import { readFileSync } from 'node:fs'

/** ELF section header, as parsed from `.shdr`. */
export interface ElfSection {
  readonly index: number
  readonly name: string
  readonly type: number
  readonly flags: number
  readonly address: number
  readonly offset: number
  readonly size: number
  readonly link: number
  readonly info: number
  readonly align: number
  readonly entrySize: number
}

/** ELF program header. */
export interface ElfSegment {
  readonly index: number
  readonly type: number
  readonly flags: number
  readonly offset: number
  readonly vaddr: number
  readonly paddr: number
  readonly fileSize: number
  readonly memSize: number
  readonly align: number
}

/** Symbols recovered from `.symtab`/`.dynsym`, used to name disassembly blocks. */
export interface ElfSymbol {
  readonly name: string
  readonly value: number
  readonly size: number
  readonly binding: string
  readonly type: string
  readonly sectionIndex: number
}

/** Everything the inspector needs to know about one binary. */
export interface ElfInfo {
  readonly path: string
  readonly size: number
  readonly elfClass: 32 | 64
  /** `ELF32` / `ELF64`, for display. */
  readonly className: 'ELF32' | 'ELF64'
  readonly endianness: 'little' | 'big'
  readonly type: number
  readonly typeName: string
  readonly machine: number
  readonly machineName: string
  /** Whether this is the architecture the tutor targets. */
  readonly isTarget: boolean
  readonly entry: number
  readonly osabi: number
  readonly sections: readonly ElfSection[]
  readonly segments: readonly ElfSegment[]
  readonly symbols: readonly ElfSymbol[]
  readonly interpreter?: string
}

const SECTION_TYPES: Record<number, string> = {
  0: 'NULL',
  1: 'PROGBITS',
  2: 'SYMTAB',
  3: 'STRTAB',
  4: 'RELA',
  5: 'HASH',
  6: 'DYNAMIC',
  7: 'NOTE',
  8: 'NOBITS',
  9: 'REL',
  10: 'SHLIB',
  11: 'DYNSYM',
  14: 'INIT_ARRAY',
  15: 'FINI_ARRAY',
  16: 'PREINIT_ARRAY',
  17: 'GROUP',
  18: 'SYMTAB_SHNDX',
}

const SEGMENT_TYPES: Record<number, string> = {
  0: 'NULL',
  1: 'LOAD',
  2: 'DYNAMIC',
  3: 'INTERP',
  4: 'NOTE',
  5: 'SHLIB',
  6: 'PHDR',
  7: 'TLS',
  0x6474e550: 'GNU_EH_FRAME',
  0x6474e551: 'GNU_STACK',
  0x6474e552: 'GNU_RELRO',
}

const ELF_TYPES: Record<number, string> = {
  0: 'NONE',
  1: 'REL',
  2: 'EXEC',
  3: 'DYN',
  4: 'CORE',
}

const MACHINES: Record<number, string> = {
  3: 'Intel 80386',
  0x3e: 'Advanced Micro Devices X86-64',
  0x28: 'ARM',
  0xb7: 'AArch64',
}

/** The architecture this plugin targets: 32-bit x86, what `ida.exe` loads. */
const TARGET_MACHINE = 3
const TARGET_CLASS = 32

const BINDINGS = ['LOCAL', 'GLOBAL', 'WEAK']
const SYMBOL_TYPES = ['NOTYPE', 'OBJECT', 'FUNC', 'SECTION', 'FILE', 'COMMON', 'TLS']

/** Header sizes per ELF class, the numbers every offset below depends on. */
const LAYOUT = {
  32: { ehdr: 52, phdr: 32, shdr: 40, sym: 16 },
  64: { ehdr: 64, phdr: 56, shdr: 64, sym: 24 },
} as const

/** Parse an ELF image. Throws when the magic is absent or the class is unsupported. */
export function parseElf(path: string): ElfInfo {
  const bytes = readFileSync(path)
  if (bytes.length < 52 || bytes[0] !== 0x7f || bytes[1] !== 0x45 || bytes[2] !== 0x4c || bytes[3] !== 0x46) {
    throw new Error(`${path} is not an ELF image (bad magic)`)
  }
  if (bytes[4] !== 1 && bytes[4] !== 2) {
    throw new Error(`${path} has an unknown ELF class byte (${bytes[4]})`)
  }
  const elfClass = (bytes[4] === 1 ? 32 : 64) as 32 | 64
  if (bytes[5] !== 1) {
    // Every challenge is little-endian; a big-endian image is reported rather than
    // silently misread.
    throw new Error(`${path} is not little-endian (EI_DATA=${bytes[5]}); only ELF little-endian is supported`)
  }
  const layout = LAYOUT[elfClass]

  const u16 = (offset: number): number => bytes.readUInt16LE(offset)
  const u32 = (offset: number): number => bytes.readUInt32LE(offset)
  /** Read an address-sized field: 4 bytes for ELF32, 8 for ELF64. */
  const addr = (offset: number): number => (elfClass === 32 ? u32(offset) : Number(bytes.readBigUInt64LE(offset)))

  const type = u16(16)
  const machine = u16(18)
  // ELF32: e_entry at 24, e_phoff at 28, e_shoff at 32, e_ehsize at 40.
  // ELF64: e_entry at 24, e_phoff at 32, e_shoff at 40, e_ehsize at 52.
  const entry = elfClass === 32 ? u32(24) : addr(24)
  const phoff = elfClass === 32 ? u32(28) : addr(32)
  const shoff = elfClass === 32 ? u32(32) : addr(40)
  const phentsize = u16(elfClass === 32 ? 42 : 54)
  const phnum = u16(elfClass === 32 ? 44 : 56)
  const shentsize = u16(elfClass === 32 ? 46 : 58)
  const shnum = u16(elfClass === 32 ? 48 : 60)
  const shstrndx = u16(elfClass === 32 ? 50 : 62)

  // --- program headers ---------------------------------------------------
  const segments: ElfSegment[] = []
  for (let index = 0; index < phnum; index += 1) {
    const base = phoff + index * (phentsize || layout.phdr)
    if (base + layout.phdr > bytes.length) break
    // ELF32 orders p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align.
    // ELF64 puts p_flags right after p_type and widens the four address fields.
    segments.push(
      elfClass === 32
        ? {
            index,
            type: u32(base),
            offset: u32(base + 4),
            vaddr: u32(base + 8),
            paddr: u32(base + 12),
            fileSize: u32(base + 16),
            memSize: u32(base + 20),
            flags: u32(base + 24),
            align: u32(base + 28),
          }
        : {
            index,
            type: u32(base),
            flags: u32(base + 4),
            offset: addr(base + 8),
            vaddr: addr(base + 16),
            paddr: addr(base + 24),
            fileSize: addr(base + 32),
            memSize: addr(base + 40),
            align: addr(base + 48),
          },
    )
  }

  // --- section headers ---------------------------------------------------
  const rawSections: { nameOffset: number; section: Omit<ElfSection, 'name'> }[] = []
  for (let index = 0; index < shnum; index += 1) {
    const base = shoff + index * (shentsize || layout.shdr)
    if (base + layout.shdr > bytes.length) break
    if (elfClass === 32) {
      rawSections.push({
        nameOffset: u32(base),
        section: {
          index,
          type: u32(base + 4),
          flags: u32(base + 8),
          address: u32(base + 12),
          offset: u32(base + 16),
          size: u32(base + 20),
          link: u32(base + 24),
          info: u32(base + 28),
          align: u32(base + 32),
          entrySize: u32(base + 36),
        },
      })
    } else {
      rawSections.push({
        nameOffset: u32(base),
        section: {
          index,
          type: u32(base + 4),
          flags: addr(base + 8),
          address: addr(base + 16),
          offset: addr(base + 24),
          size: addr(base + 32),
          link: u32(base + 40),
          info: u32(base + 44),
          align: addr(base + 48),
          entrySize: addr(base + 56),
        },
      })
    }
  }

  const nameTable = shstrndx < rawSections.length ? rawSections[shstrndx] : undefined
  const sectionName = (nameOffset: number): string =>
    nameTable === undefined ? '' : readCString(bytes, nameTable.section.offset + nameOffset, 256)

  const sections: ElfSection[] = rawSections.map(raw => ({ ...raw.section, name: sectionName(raw.nameOffset) }))

  // --- symbols -----------------------------------------------------------
  const symbols: ElfSymbol[] = []
  for (const section of sections) {
    if (section.type !== 2 && section.type !== 11) continue
    const strtab = sections[section.link]
    if (strtab === undefined) continue
    const size = section.entrySize || layout.sym
    const count = size > 0 ? Math.floor(section.size / size) : 0
    for (let index = 0; index < count; index += 1) {
      const base = section.offset + index * size
      if (base + layout.sym > bytes.length) break
      const name = readCString(bytes, strtab.offset + u32(base), 512)
      // ELF32: st_value +4, st_size +8, st_info +12, st_shndx +14.
      // ELF64: st_info +4, st_shndx +6, st_value +8, st_size +16.
      const info = bytes[elfClass === 32 ? base + 12 : base + 4] ?? 0
      symbols.push({
        name,
        value: elfClass === 32 ? u32(base + 4) : addr(base + 8),
        size: elfClass === 32 ? u32(base + 8) : addr(base + 16),
        binding: BINDINGS[(info >> 4) & 0xf] ?? 'UNKNOWN',
        type: SYMBOL_TYPES[info & 0xf] ?? 'UNKNOWN',
        sectionIndex: u16(elfClass === 32 ? base + 14 : base + 6),
      })
    }
  }

  const interp = segments.find(segment => segment.type === 3)
  const interpreter =
    interp === undefined ? undefined : readCString(bytes, interp.offset, Math.min(interp.fileSize, 256))

  return {
    path,
    size: bytes.length,
    elfClass,
    className: elfClass === 32 ? 'ELF32' : 'ELF64',
    endianness: 'little',
    type,
    typeName: ELF_TYPES[type] ?? `0x${type.toString(16)}`,
    machine,
    machineName: MACHINES[machine] ?? `machine 0x${machine.toString(16)}`,
    isTarget: machine === TARGET_MACHINE && elfClass === TARGET_CLASS,
    entry,
    osabi: bytes[7] ?? 0,
    sections,
    segments,
    symbols,
    ...(interpreter === undefined ? {} : { interpreter }),
  }
}

function readCString(bytes: Buffer, offset: number, maxLength: number): string {
  if (offset < 0 || offset >= bytes.length) return ''
  let end = offset
  const limit = Math.min(bytes.length, offset + maxLength)
  while (end < limit && bytes[end] !== 0) end += 1
  return bytes.subarray(offset, end).toString('utf8')
}

/** Whether a parsed image is the architecture the challenges are built for. */
export function isTargetArchitecture(info: ElfInfo): boolean {
  return info.isTarget
}

/** Render the banner plus header facts, in the shape `file(1)` uses. */
export function renderFileView(info: ElfInfo): string {
  const typeWord = info.type === 3 ? 'shared object' : info.type === 2 ? 'executable' : 'relocatable'
  const bits = info.elfClass === 32 ? '32-bit' : '64-bit'
  const targetNote = info.isTarget
    ? 'opens in ida.exe (the 32-bit build)'
    : info.elfClass === 64
      ? "WARNING: 64-bit binary — IDA's 32-bit build (ida.exe) cannot load it"
      : 'WARNING: not the architecture this tutor builds for'
  return [
    `${info.path}: ELF ${bits} LSB ${typeWord}, ${info.machineName}, statically linked, stripped`,
    `[${targetNote}]`,
    '',
    `size: ${info.size} bytes`,
    `class: ${info.className}`,
    `type: ${info.typeName} (${info.type})`,
    `machine: ${info.machineName} (${info.machine})`,
    `entry point: 0x${info.entry.toString(16)}`,
    `program headers: ${info.segments.length}`,
    `section headers: ${info.sections.length}`,
    `interpreter: ${info.interpreter ?? '(none — static, no dynamic loader)'}`,
    `symbol table entries: ${info.symbols.length}${info.symbols.length === 0 ? ' (stripped)' : ''}`,
  ].join('\n')
}

/** Render the section and program headers in `readelf`'s column layout. */
export function renderReadelfView(info: ElfInfo, options: { readonly limit?: number } = {}): string {
  const limit = options.limit ?? 40
  // Address width follows the class: 8 hex digits for ELF32, 16 for ELF64.
  const width = info.elfClass === 32 ? 8 : 16
  const hex = (value: number): string => `0x${value.toString(16).padStart(width, '0')}`
  const lines: string[] = []
  lines.push('ELF Header:')
  lines.push(`  Class:                             ${info.className}`)
  lines.push(`  Data:                              2's complement, little endian`)
  lines.push(`  Type:                              ${info.typeName}`)
  lines.push(`  Machine:                           ${info.machineName}`)
  lines.push(`  Entry point address:               ${hex(info.entry)}`)
  lines.push('')
  lines.push('Program Headers:')
  lines.push('  Type           Offset     VirtAddr   FileSiz    MemSiz     Flg Align')
  for (const segment of info.segments.slice(0, limit)) {
    lines.push(
      `  ${(SEGMENT_TYPES[segment.type] ?? 'UNKNOWN').padEnd(14)} ` +
        `${hex(segment.offset)} ` +
        `${hex(segment.vaddr)} ` +
        `${hex(segment.fileSize)} ` +
        `${hex(segment.memSize)} ` +
        `${renderFlags(segment.flags)}  ${hex(segment.align)}`,
    )
  }
  lines.push('')
  lines.push('Section Headers:')
  lines.push('  [Nr] Name              Type            Address    Offset     Size       ES Flg Lk Inf Al')
  for (const section of info.sections.slice(0, limit)) {
    lines.push(
      `  [${String(section.index).padStart(2, ' ')}] ` +
        `${section.name.padEnd(17)} ` +
        `${(SECTION_TYPES[section.type] ?? 'UNKNOWN').padEnd(15)} ` +
        `${hex(section.address)} ` +
        `${hex(section.offset)} ` +
        `${hex(section.size)} ` +
        `${String(section.entrySize).padStart(2, ' ')} ` +
        `${renderSectionFlags(section.flags)}   ` +
        `${String(section.link).padStart(2, ' ')} ` +
        `${String(section.info).padStart(3, ' ')} ` +
        `${hex(section.align)}`,
    )
  }
  if (info.sections.length > limit) {
    lines.push(`  ... ${info.sections.length - limit} more sections omitted`)
  }
  if (info.symbols.length > 0) {
    lines.push('')
    lines.push('Symbol table (.symtab and .dynsym):')
    for (const symbol of info.symbols.slice(0, limit)) {
      lines.push(
        `  ${hex(symbol.value)} ${String(symbol.size).padStart(6, ' ')} ` +
          `${symbol.type.padEnd(7)} ${symbol.binding.padEnd(6)} ${symbol.name}`,
      )
    }
  }
  return lines.join('\n')
}

function renderFlags(flags: number): string {
  return `${(flags & 4) !== 0 ? 'R' : ' '}${(flags & 2) !== 0 ? 'W' : ' '}${(flags & 1) !== 0 ? 'E' : ' '}`
}

function renderSectionFlags(flags: number): string {
  const map: [number, string][] = [
    [0x1, 'W'],
    [0x2, 'A'],
    [0x4, 'X'],
    [0x10, 'M'],
    [0x20, 'S'],
    [0x40, 'I'],
  ]
  return map.filter(([bit]) => (flags & bit) !== 0).map(([, letter]) => letter).join('') || ' '
}

/** Extract printable ASCII runs, the way `strings(1)` does. */
export function extractStrings(
  path: string,
  options: { readonly minLength?: number; readonly maxCount?: number } = {},
): { offset: number; text: string }[] {
  const minLength = options.minLength ?? 4
  const maxCount = options.maxCount ?? 400
  const bytes = readFileSync(path)
  const found: { offset: number; text: string }[] = []
  let run: number[] = []
  let runStart = 0

  const flush = (): void => {
    if (run.length >= minLength) {
      found.push({ offset: runStart, text: Buffer.from(run).toString('latin1') })
    }
    run = []
  }

  for (let index = 0; index < bytes.length; index += 1) {
    const byte = bytes[index]!
    const printable = byte === 0x09 || (byte >= 0x20 && byte < 0x7f)
    if (printable) {
      if (run.length === 0) runStart = index
      run.push(byte)
      continue
    }
    flush()
    if (found.length >= maxCount * 4) break
  }
  flush()
  return found.slice(0, maxCount)
}

/** Render the string list with file offsets, deduplicated. */
export function renderStringsView(
  path: string,
  options: { readonly minLength?: number; readonly maxCount?: number } = {},
): string {
  const entries = extractStrings(path, options)
  if (entries.length === 0) return 'no printable strings found'
  const seen = new Set<string>()
  const lines: string[] = []
  for (const entry of entries) {
    // Challenges print the same banner twice; show each distinct string once.
    if (seen.has(entry.text)) continue
    seen.add(entry.text)
    lines.push(`0x${entry.offset.toString(16).padStart(6, '0')}  ${entry.text}`)
  }
  return lines.join('\n')
}

/** Address-to-file-offset translation using the program headers. */
export function addressToOffset(info: ElfInfo, address: number): number | undefined {
  for (const segment of info.segments) {
    if (segment.type !== 1) continue
    if (address >= segment.vaddr && address < segment.vaddr + segment.fileSize) {
      return segment.offset + (address - segment.vaddr)
    }
  }
  return undefined
}

/** Read `length` bytes at a virtual address. */
export function readAtAddress(info: ElfInfo, address: number, length: number): Buffer | undefined {
  const offset = addressToOffset(info, address)
  if (offset === undefined) return undefined
  const bytes = readFileSync(info.path)
  return bytes.subarray(offset, Math.min(bytes.length, offset + length))
}

/** Read a NUL-terminated string at a virtual address. */
export function stringAtAddress(info: ElfInfo, address: number, maxLength = 256): string | undefined {
  const bytes = readAtAddress(info, address, maxLength)
  if (bytes === undefined) return undefined
  let end = 0
  while (end < bytes.length && bytes[end] !== 0) end += 1
  return bytes.subarray(0, end).toString('latin1')
}
