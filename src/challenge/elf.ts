/**
 * A minimal, deterministic **ELF32 i386** emitter: the compiler-free fallback.
 *
 * Real compiler builds are always preferred — the implementation spec asks for
 * `gcc`/`clang`, and a compiled challenge is the richest artefact for IDA Pro.
 * This module exists for the host where no compiler can target 32-bit Linux, and
 * it exists at all so a build never silently degrades into something the student
 * cannot use: a PE, or a 64-bit ELF that `ida.exe` refuses to open.
 *
 * The fallback emits a genuine, runnable `ELFCLASS32 / EM_386` executable with the
 * same observable contract as a compiled challenge: it prints a prompt, reads one
 * line from stdin, and exits 0 exactly when the accepted value was entered. The
 * accepted length is checked first, and a mismatch exits non-zero without ever
 * touching the reference data.
 *
 * The emitter is a small assembler rather than a bytecode interpreter: each
 * template gets a hand-written instruction sequence, so the disassembly still looks
 * like compiled i386 code (`push ebp / mov ebp, esp`, a counted loop, `int 0x80`)
 * and a student can trace the transform in IDA Pro.
 *
 * Output is byte-stable for a given input, so a fallback build is reproducible.
 *
 * @module dsh-reverse-tutor/challenge/elf
 */

import type { TransformSpec } from './templates.js'

/* ------------------------------------------------------------------------ */
/* Encoding helpers                                                          */
/* ------------------------------------------------------------------------ */

/** Register indices, including the 8/16-bit names the emitter spells out. */
const R = {
  eax: 0,
  al: 0,
  ecx: 1,
  cl: 1,
  edx: 2,
  ebx: 3,
  bl: 3,
  esp: 4,
  ebp: 5,
  esi: 6,
  edi: 7,
} as const

type Register = keyof typeof R

/** `u32` little-endian bytes. */
function u32(value: number): number[] {
  const normalized = value >>> 0
  return [normalized & 0xff, (normalized >>> 8) & 0xff, (normalized >>> 16) & 0xff, (normalized >>> 24) & 0xff]
}

/** ModR/M byte. */
function modrm(mod: number, reg: number, rm: number): number {
  return ((mod & 3) << 6) | ((reg & 7) << 3) | (rm & 7)
}

/** SIB byte, for `[base + index*scale]` addressing. */
function sib(scale: number, index: number, base: number): number {
  return ((scale & 3) << 6) | ((index & 7) << 3) | (base & 7)
}

/**
 * x86 instruction buffer with the i386 encodings this emitter needs.
 *
 * Everything here is 32-bit: no REX prefix, addresses and immediates are four
 * bytes, and the syscall instruction is `int 0x80`.
 */
class Asm {
  private readonly code: number[] = []

  get length(): number {
    return this.code.length
  }

  emit(...bytes: number[]): this {
    this.code.push(...bytes)
    return this
  }

  /** `mov r32, imm32` (B8+rd). */
  movImm32(register: Register, value: number): this {
    return this.emit(0xb8 + R[register], ...u32(value))
  }

  /** `mov r32, r32` (89 /r). */
  movReg(destination: Register, source: Register): this {
    return this.emit(0x89, modrm(3, R[source], R[destination]))
  }

  /** `mov r32, [base + disp32]` (8B /r with mod=10). */
  movRegDisp32(destination: Register, base: Register, displacement: number): this {
    this.emit(0x8b, modrm(0b10, R[destination], R[base]))
    return this.emit(...u32(displacement))
  }

  /** `mov [base + disp32], r32` (89 /r with mod=10). */
  movDisp32Reg(base: Register, displacement: number, source: Register): this {
    this.emit(0x89, modrm(0b10, R[source], R[base]))
    return this.emit(...u32(displacement))
  }

  /** `lea r32, [base + index]` (8D /r with mod=00, rm=100 plus SIB). */
  leaRegBaseIndex(destination: Register, base: Register, index: Register): this {
    this.emit(0x8d, modrm(0b00, R[destination], 0b100), sib(0, R[index], R[base]))
    return this
  }

  /**
   * `mov r32, [index*4 + disp32]` (8B /r with mod=00, rm=100, SIB base=101).
   *
   * This is how a `static const int[]` is indexed in 32-bit code: the array's
   * absolute address is the 32-bit displacement and the index is scaled by 4. The
   * shape is distinctive enough that a student can spot the reference array from
   * one instruction.
   */
  movRegScaledIndexed(destination: Register, index: Register, address: number): this {
    this.emit(0x8b, modrm(0b00, R[destination], 0b100), sib(2, R[index], 0b101))
    return this.emit(...u32(address))
  }

  /**
   * `mov r32, [disp32]` (8B /r with mod=00, rm=101).
   *
   * Absolute addressing, which is how 32-bit non-PIE code reads a global: the
   * address is the displacement. This is the form used for every `.rodata`
   * parameter the generated code needs.
   */
  movRegAbs(destination: Register, address: number): this {
    this.emit(0x8b, modrm(0b00, R[destination], 0b101))
    return this.emit(...u32(address))
  }

  /** `mov r8, r8` (88 /r) — a byte move between 8-bit register encodings. */
  movRegReg8(destination: Register, source: Register): this {
    return this.emit(0x88, modrm(3, R[source], R[destination]))
  }

  /** `sub r32, r32` (29 /r). */
  subReg32(destination: Register, source: Register): this {
    return this.emit(0x29, modrm(3, R[source], R[destination]))
  }

  /**
   * `movzx r32, byte [base + index]` (0F B6 /r, mod=01, rm=100, disp8 = 0).
   *
   * mod=01 with a zero disp8 rather than mod=00: `mod=00, base=101` is the reserved
   * encoding for absolute `disp32` addressing, so a base whose encoding is 5 (EBP)
   * cannot use mod=00 at all. Every stride-1 form in this generator therefore goes
   * through mod=01 with an explicit zero, which is also what a compiler emits when
   * it wants `[reg+reg]` from a base in that slot.
   *
   * The idiom in the listing is `movzx eax, byte ptr [ebp + ecx]`.
   */
  movzxByteBaseIndex(destination: Register, base: Register, index: Register): this {
    this.emit(0x0f, 0xb6, modrm(0b01, R[destination], 0b100), sib(0, R[index], R[base]), 0x00)
    return this
  }

  /**
   * `mov r32, [index*4 + disp32]` (8B /r, mod=00, rm=100, SIB base=101 = disp32).
   *
   * Absolute scaled addressing: `mov ebx, dword ptr [ecx*4 + 0x804a020]`. This is
   * the form a compiler emits for `static const int rt_target[]`, and it is how the
   * arithmetic and branch templates compare against a 32-bit array without loading
   * its base into a register first.
   */
  movScaledIndexed(destination: Register, index: Register, address: number): this {
    this.emit(0x8b, modrm(0b00, R[destination], 0b100), sib(2, R[index], 0b101))
    return this.emit(...u32(address))
  }

  /**
   * `movzx r32, byte [index + disp32]` (0F B6 /r, mod=00, rm=100, SIB base=101).
   *
   * The byte-array counterpart: `movzx ebx, byte ptr [ecx + 0x804a020]`.
   */
  movzxAbsIndexed(destination: Register, index: Register, address: number): this {
    this.emit(0x0f, 0xb6, modrm(0b00, R[destination], 0b100), sib(0, R[index], 0b101))
    return this.emit(...u32(address))
  }

  /** `movzx r32, byte [base + disp32]` (0F B6 /r with mod=10). */
  movzxByteDisp32(destination: Register, base: Register, displacement: number): this {
    this.emit(0x0f, 0xb6, modrm(0b10, R[destination], R[base]))
    return this.emit(...u32(displacement))
  }

  /** `movzx r32, r8` (0F B6 /r). */
  movzxByteReg(destination: Register, source: Register): this {
    return this.emit(0x0f, 0xb6, modrm(3, R[destination], R[source]))
  }

  /** `cmp r32, imm32` (81 /7). */
  cmpImm32(register: Register, value: number): this {
    this.emit(0x81, modrm(3, 7, R[register]), ...u32(value))
    return this
  }

  /** `cmp r32, imm8` (83 /7, sign-extended). */
  cmpSignedImm8(register: Register, value: number): this {
    return this.emit(0x83, modrm(3, 7, R[register]), value & 0xff)
  }

  /**
   * `cmp r32, imm32` for an unsigned range test (81 /7 with a zero-extended 0..255
   * immediate).
   *
   * Sign-extending a byte into a 32-bit register is fine while the value stays below
   * 128, and `cmpSignedImm8` covers that. It stops being fine the moment a template
   * wants to compare against something like 144: `83 /7` would encode that as
   * `0xffffff90` and the comparison would silently mean something else. The 32-bit
   * immediate costs three extra bytes and is never wrong.
   */
  cmpUnsignedImm8(register: Register, value: number): this {
    return this.cmpImm32(register, value & 0xff)
  }

  /** `cmp r32, r32` (39 /r). */
  cmpReg(destination: Register, source: Register): this {
    return this.emit(0x39, modrm(3, R[source], R[destination]))
  }

  /** `cmp r32, byte [base + disp32]` (38 /r with mod=10). */
  cmpDisp32Imm8(base: Register, displacement: number, value: number): this {
    this.emit(0x80, modrm(0b10, 7, R[base]))
    this.emit(...u32(displacement), value & 0xff)
    return this
  }

  /** `add r32, imm32` (81 /0). */
  addImm32(register: Register, value: number): this {
    this.emit(0x81, modrm(3, 0, R[register]), ...u32(value))
    return this
  }

  /** `add r32, r32` (01 /r). */
  addReg(destination: Register, source: Register): this {
    return this.emit(0x01, modrm(3, R[source], R[destination]))
  }

  /** `sub r32, imm32` (81 /5). */
  subImm32(register: Register, value: number): this {
    this.emit(0x81, modrm(3, 5, R[register]), ...u32(value))
    return this
  }

  /** `sub r32, imm8` (83 /5, sign-extended). */
  subImm8(register: Register, value: number): this {
    return this.emit(0x83, modrm(3, 5, R[register]), value & 0xff)
  }

  /** `add r32, imm8` (83 /0, sign-extended). */
  addImm8(register: Register, value: number): this {
    return this.emit(0x83, modrm(3, 0, R[register]), value & 0xff)
  }

  /** `imul r32, imm32` (69 /r). */
  imulImm32(register: Register, value: number): this {
    this.emit(0x69, modrm(3, R[register], R[register]), ...u32(value))
    return this
  }

  /** `imul r32, r32` (0F AF /r). */
  imulReg(destination: Register, source: Register): this {
    return this.emit(0x0f, 0xaf, modrm(3, R[destination], R[source]))
  }

  /** `xor r32, imm32` (81 /6). */
  xorImm32(register: Register, value: number): this {
    this.emit(0x81, modrm(3, 6, R[register]), ...u32(value))
    return this
  }

  /** `xor r32, r32` (31 /r). */
  xorReg(destination: Register, source: Register): this {
    return this.emit(0x31, modrm(3, R[source], R[destination]))
  }

  /** `shl r32, imm8` (C1 /4). */
  shlImm8(register: Register, value: number): this {
    return this.emit(0xc1, modrm(3, 4, R[register]), value & 0xff)
  }

  /** `shr r32, imm8` (C1 /5). */
  shrImm8(register: Register, value: number): this {
    return this.emit(0xc1, modrm(3, 5, R[register]), value & 0xff)
  }

  /** `shr r32, cl` (D3 /5). */
  shrByCl(register: Register): this {
    return this.emit(0xd3, modrm(3, 5, R[register]))
  }

  /** `and r32, imm8` (83 /4, sign-extended). */
  andImm8(register: Register, value: number): this {
    return this.emit(0x83, modrm(3, 4, R[register]), value & 0xff)
  }

  /** `mul r32` (F7 /4): EDX:EAX = EAX * operand. */
  mulReg(register: Register): this {
    return this.emit(0xf7, modrm(3, 4, R[register]))
  }

  /** `inc r32` (40+rd). */
  incReg(register: Register): this {
    return this.emit(0x40 + R[register])
  }

  /** `dec r32` (48+rd). */
  decReg(register: Register): this {
    return this.emit(0x48 + R[register])
  }

  /** `push r32` (50+rd). */
  push(register: Register): this {
    return this.emit(0x50 + R[register])
  }

  /** `pop r32` (58+rd). */
  pop(register: Register): this {
    return this.emit(0x58 + R[register])
  }

  /** `int imm8` — `int 0x80` is the i386 kernel-call instruction. */
  int(vector: number): this {
    return this.emit(0xcd, vector & 0xff)
  }

  /** `ret` (C3). */
  ret(): this {
    return this.emit(0xc3)
  }

  /** `leave` (C9): `mov esp, ebp` + `pop ebp`. */
  leave(): this {
    return this.emit(0xc9)
  }

  /** `nop` (90). */
  nop(): this {
    return this.emit(0x90)
  }

  /** `hlt` (F4). */
  hlt(): this {
    return this.emit(0xf4)
  }

  /** Emit a `jcc rel32` with a placeholder displacement; returns the patch site. */
  private jcc(opcode: number, target: number | 'unresolved'): number {
    this.emit(0x0f, opcode)
    const site = this.code.length
    this.emit(0, 0, 0, 0)
    if (target !== 'unresolved') this.patchRel32(site, target)
    return site
  }

  je(target: number | 'unresolved'): number {
    return this.jcc(0x84, target)
  }

  jne(target: number | 'unresolved'): number {
    return this.jcc(0x85, target)
  }

  jae(target: number | 'unresolved'): number {
    return this.jcc(0x83, target)
  }

  jb(target: number | 'unresolved'): number {
    return this.jcc(0x82, target)
  }

  jmp(target: number | 'unresolved'): number {
    this.emit(0xe9)
    const site = this.code.length
    this.emit(0, 0, 0, 0)
    if (target !== 'unresolved') this.patchRel32(site, target)
    return site
  }

  /** Resolve a `rel32` placeholder recorded earlier. */
  patchRel32(site: number, target: number): this {
    const displacement = u32(target - (site + 4))
    for (let index = 0; index < 4; index += 1) this.code[site + index] = displacement[index]!
    return this
  }

  /** Append a NUL-terminated string to the buffer, returning its offset. */
  appendString(text: string): number {
    const offset = this.code.length
    for (const character of text) this.code.push(character.charCodeAt(0) & 0xff)
    this.code.push(0)
    return offset
  }

  /** Pad the buffer with `nop` bytes to an alignment. */
  alignTo(boundary: number): this {
    while (this.code.length % boundary !== 0) this.code.push(0x90)
    return this
  }

  toBuffer(): Buffer {
    return Buffer.from(this.code)
  }
}

/* ------------------------------------------------------------------------ */
/* Program layout                                                            */
/* ------------------------------------------------------------------------ */

/**
 * Fixed addresses the fallback artefact is built around: the classic i386
 * non-PIE image. IDA's default base for this architecture is 0x08048000, so the
 * addresses the tutor quotes are the ones the student sees.
 */
export const SEGMENT_BASE = 0x0804_8000
/** Where the kernel enters: one page after the headers, as a linker would place it. */
export const TEXT_ADDRESS = SEGMENT_BASE + 0x1000
/** File offset and virtual offset of `.rodata`: its own page after the code. */
export const DATA_OFFSET = 0x2000
/** Input scratch buffer offset inside the mapped segment. */
export const INPUT_OFFSET = 0x2000
/** Longest accepted input line, mirroring `RT_MAX_LINE`. */
export const INPUT_CAPACITY = 255

const EHDR_SIZE = 52
const PHDR_SIZE = 32
const PAGE_SIZE = 0x1000

/** i386 Linux syscall numbers. */
const SYS_EXIT = 1
const SYS_READ = 3
const SYS_WRITE = 4

/** Strings every fallback challenge uses, byte-identical to the templates. */
export const FALLBACK_STRINGS = {
  banner: '== Reverse Tutor ==\n',
  prompt: 'Enter the accepted value: ',
  accepted: 'accepted\n',
  rejected: 'rejected\n',
  noInput: 'no input\n',
} as const

/* ------------------------------------------------------------------------ */
/* Code generation                                                           */
/* ------------------------------------------------------------------------ */

/*
 * Register plan for the generated program. It mirrors what a 32-bit compiler would
 * pick for this shape, so the listing reads the way a 32-bit crackme should:
 *
 *   ebp  pointer to the user's input      ebx  loop scratch / reference byte
 *   ecx  loop index                       edx  accepted length, then multiply scratch
 *   eax  byte under test, and the syscall number
 *   esi/edi  arithmetic scale and bias (only for the arithmetic template)
 */

/** Where each piece of the generated `.rodata` lands, once `.text` has been sized. */
interface RodataPlan {
  /** Absolute address of the banner, which is also the start of `.rodata`. */
  readonly base: number
  /** Absolute addresses of the five message strings. */
  readonly message: Readonly<Record<keyof typeof FALLBACK_STRINGS, number>>
  /** Byte length of each message, including its trailing NUL. */
  readonly messageLength: Readonly<Record<keyof typeof FALLBACK_STRINGS, number>>
  /** Absolute address of the transform parameters, as 32-bit words. */
  readonly parameters: number
  /** Absolute address of the reference data. */
  readonly reference: number
}

/**
 * The generated `.rodata`, in one fixed order: the five message strings, then the
 * transform parameters as 32-bit words, then the reference data as bytes.
 *
 * Keeping the order fixed is what lets the code generator compute every address
 * from two numbers — the base and the reference offset — instead of threading a
 * symbol table through the assembler.
 */
function planRodata(spec: TransformSpec, base: number): RodataPlan {
  const banner = bannerFor(spec)
  const messages: Record<keyof typeof FALLBACK_STRINGS, string> = {
    ...FALLBACK_STRINGS,
    banner,
  }
  let offset = 0
  const message = {} as Record<keyof typeof FALLBACK_STRINGS, number>
  const messageLength = {} as Record<keyof typeof FALLBACK_STRINGS, number>
  for (const key of MESSAGE_ORDER) {
    message[key] = base + offset
    // Every message is stored NUL-terminated so `strings` shows one clean run.
    messageLength[key] = messages[key].length
    offset += messages[key].length + 1
  }
  while (offset % 4 !== 0) offset += 1
  const parameters = base + offset
  offset += transformParameters(spec).length * 4
  while (offset % 4 !== 0) offset += 1
  const reference = base + offset
  return { base, message, messageLength, parameters, reference }
}

/** The five message strings, each stored NUL-terminated. */
function buildRodataBytes(spec: TransformSpec, base: number): Buffer {
  const plan = planRodata(spec, base)
  const banner = bannerFor(spec)
  const messages: Record<keyof typeof FALLBACK_STRINGS, string> = { ...FALLBACK_STRINGS, banner }
  const bytes: number[] = []
  for (const key of MESSAGE_ORDER) {
    for (const character of messages[key]) bytes.push(character.charCodeAt(0) & 0xff)
    bytes.push(0)
  }
  while (bytes.length % 4 !== 0) bytes.push(0)
  for (const value of transformParameters(spec)) bytes.push(...u32(value))
  while (bytes.length % 4 !== 0) bytes.push(0)
  // The reference data's element width must match how the code reads it: only the
  // arithmetic template indexes a 32-bit `rt_target[ecx]`, and every byte-wise
  // transform reads one byte per position. Writing the wrong width does not fault —
  // the program simply compares against garbage and rejects its own accepted value,
  // which is the single worst failure this file can have.
  if (referenceIsWordWide(spec)) {
    for (const value of spec.reference) bytes.push(...u32(value))
  } else {
    for (const value of spec.reference) bytes.push(value & 0xff)
  }
  // The plan is computed from the same layout, so a mismatch here would be an
  // internal contradiction rather than a caller error.
  const referenceBytes = referenceIsWordWide(spec) ? spec.reference.length * 4 : spec.reference.length
  if (bytes.length !== plan.reference + referenceBytes - base) {
    throw new Error('reverse-tutor: internal rodata layout mismatch')
  }
  return Buffer.from(bytes)
}

/** The banner a template shows, matching the compiled source's first `rt_puts`. */
function bannerFor(spec: TransformSpec): string {
  return spec.banner
}

const MESSAGE_ORDER = ['banner', 'prompt', 'accepted', 'rejected', 'noInput'] as const

/**
 * The transform parameters, as 32-bit words, in the order the code reads them.
 *
 * Every template's parameters go through this one function so the emitter and the
 * rodata writer cannot disagree about what is stored where.
 */
function transformParameters(spec: TransformSpec): number[] {
  switch (spec.kind) {
    case 'xor-broadcast':
    case 'xor-rotating':
      // key bytes, one word each
      return [...spec.parameters]
    case 'xor-keystream':
      // seedLo, seedHi, mulLo, mulHi, incLo, incHi, shift — already in that order
      return [...spec.parameters]
    case 'arithmetic':
      // scale, bias, biasStep
      return spec.parameters.slice(0, 3)
    case 'branch':
      // gate, biasLow, biasHigh
      return spec.parameters.slice(0, 3)
    case 'direct':
    default:
      return []
  }
}

/**
 * How the reference data is compared: byte-wise, or as 32-bit elements.
 *
 * `arithmetic` is the only transform whose reference values exceed a byte — each
 * element is `(code + index) * scale - bias`, which runs into the hundreds. Every
 * other transform, `branch` included, produces one byte per position even though
 * the running value is held in EAX, so their tables must stay byte-wide. Reading a
 * byte-wide table with a 32-bit load is silent: the program compares against
 * garbage and rejects its own accepted value.
 */
function referenceIsWordWide(spec: TransformSpec): boolean {
  return spec.kind === 'arithmetic'
}

/**
 * Assemble one fallback challenge's `.text`.
 *
 * `rodataBase` and `inputBase` are parameters rather than constants because the
 * addresses depend on the size of `.text`, which is only known after assembling.
 * Callers assemble twice, exactly as a linker resolves two passes.
 */
export function assembleProgram(spec: TransformSpec, rodataBase: number, inputBase: number): Buffer {
  const asm = new Asm()
  const plan = planRodata(spec, rodataBase)

  /** `write(1, <message>, length)` with the kernel arguments in EBX/ECX/EDX. */
  const writeMessage = (name: keyof typeof FALLBACK_STRINGS): void => {
    asm.movImm32('eax', SYS_WRITE)
    asm.movImm32('ebx', 1)
    asm.movImm32('ecx', plan.message[name])
    asm.movImm32('edx', plan.messageLength[name])
    asm.int(0x80)
  }

  /** `exit(code)` with the status in EBX. */
  const exitWith = (code: number): void => {
    asm.movImm32('eax', SYS_EXIT)
    asm.movImm32('ebx', code)
    asm.int(0x80)
    asm.hlt()
  }

  // --- entry ------------------------------------------------------------
  // A cdecl-style frame, because that is the shape a student expects to read.
  asm.push('ebp')
  asm.movReg('ebp', 'esp')
  asm.subImm32('esp', 0x100)

  writeMessage('banner')
  writeMessage('prompt')

  // --- read(0, buffer, 255) --------------------------------------------
  asm.movImm32('eax', SYS_READ)
  asm.movImm32('ebx', 0)
  asm.movImm32('ecx', inputBase)
  asm.movImm32('edx', INPUT_CAPACITY)
  asm.int(0x80)

  asm.cmpImm32('eax', 0)
  const hasInput = asm.jne('unresolved')
  writeMessage('noInput')
  exitWith(2)
  asm.patchRel32(hasInput, asm.length)

  // --- strlen(input) ----------------------------------------------------
  // EBP becomes the input pointer; EDX counts bytes.
  asm.movImm32('ebp', inputBase)
  asm.xorReg('edx', 'edx')
  const lengthLoop = asm.length
  emitCmpByteBaseIndex(asm, 'ebp', 'edx', 0)
  const lengthDone = asm.je('unresolved')
  asm.incReg('edx')
  asm.jmp(lengthLoop)
  asm.patchRel32(lengthDone, asm.length)

  // Strip one trailing LF, then require the exact accepted length.
  asm.cmpImm32('edx', 0)
  const noTrim = asm.je('unresolved')
  asm.movReg('ecx', 'edx')
  asm.decReg('ecx')
  asm.movzxByteBaseIndex('eax', 'ebp', 'ecx')
  asm.cmpSignedImm8('eax', 0x0a)
  const afterTrim = asm.jne('unresolved')
  asm.decReg('edx')
  asm.patchRel32(noTrim, asm.length)
  asm.patchRel32(afterTrim, asm.length)

  // The accepted length is checked before any reference data is consulted, so a
  // wrong-length answer never even reaches the comparison loop.
  asm.cmpImm32('edx', spec.length)
  const lengthMatches = asm.je('unresolved')

  // --- reject / accept paths -------------------------------------------
  const rejectLabel = asm.length
  writeMessage('rejected')
  exitWith(1)

  const acceptLabel = asm.length
  writeMessage('accepted')
  exitWith(0)

  // --- transform loop ---------------------------------------------------
  // ECX is the index, EDX the accepted length (restored below because the multiply
  // and comparison use it), and EBX the reference byte for the current index.
  // --- transform loop ---------------------------------------------------
  // Contract, and every template below relies on it: `transformBody` leaves the
  // TRANSFORMED byte in EAX. The input byte is loaded here so the keystream can
  // start from a known state, and the reference value is loaded after.
  asm.patchRel32(lengthMatches, asm.length)
  asm.xorReg('ecx', 'ecx')
  transformSetup(asm, spec)

  const body = asm.length
  transformBody(asm, spec, plan)
  loadReferenceByte(asm, spec, plan)
  asm.cmpReg('eax', 'ebx')
  const mismatch = asm.jne('unresolved')
  asm.incReg('ecx')
  asm.cmpImm32('ecx', spec.length)
  const loopContinue = asm.jne('unresolved')
  asm.patchRel32(loopContinue, body)
  asm.jmp(acceptLabel)
  asm.patchRel32(mismatch, rejectLabel)

  return asm.toBuffer()
}

/**
 * `cmp byte ptr [base + index], 0` — the strlen inner test.
 *
 * Emitted directly because it is the one place this generator needs the stride-1
 * byte-compare form, and spelling the encoding here keeps the Asm helper set small.
 *
 * Three things are load-bearing:
 *
 * - `sib(0, index, base)` puts the index in bits 3–5 and the base in bits 0–2;
 * - `mod=01` with an explicit zero disp8, because `mod=00` with a base whose
 *   encoding is 5 (EBP) means absolute `disp32` and would read the instruction
 *   stream instead of the input buffer;
 * - passing `0b101` as the base would do the same thing even with a different mod.
 */
function emitCmpByteBaseIndex(asm: Asm, base: Register, index: Register, value: number): void {
  asm.emit(0x80, modrm(0b01, 7, 0b100), sib(0, R[index], R[base]), 0x00, value & 0xff)
}

/**
 * Load the reference value for the current index into EBX.
 *
 * Byte-wise transforms compare against `rt_target[ecx]`; the arithmetic and branch
 * templates compare against a 32-bit `rt_target[ecx]`, which is the same
 * `mov ebx, [ebx + ecx*4]` idiom a compiler emits for a `static const int[]`.
 *
 * The loop index lives in ECX, so the byte-load form uses the absolute address of
 * the reference array in the displacement and ECX as the index register — the exact
 * `movzx ebx, byte ptr [ecx + <target>]` shape a compiler produces for the same
 * source.
 */
function loadReferenceByte(asm: Asm, spec: TransformSpec, plan: RodataPlan): void {
  if (referenceIsWordWide(spec)) {
    asm.movScaledIndexed('ebx', 'ecx', plan.reference)
    return
  }
  asm.movzxAbsIndexed('ebx', 'ecx', plan.reference)
}

/** Per-template parameter setup, emitted immediately before the loop. */
function transformSetup(asm: Asm, spec: TransformSpec): void {
  switch (spec.kind) {
    case 'arithmetic':
      // ESI = scale, EDI = bias (which advances per index when biasStep is set)
      asm.movImm32('esi', spec.parameters[0] ?? 1)
      asm.movImm32('edi', spec.parameters[1] ?? 0)
      break
    default:
      break
  }
}

/**
 * Per-template per-character transform, emitted inside the loop.
 *
 * Contract: each branch loads the input byte itself and leaves the TRANSFORMED byte
 * in EAX. Loading it here rather than in the loop header is what lets the keystream
 * template reserve EAX for its own scratch work without the input byte being
 * clobbered on the way.
 */
function transformBody(asm: Asm, spec: TransformSpec, plan: RodataPlan): void {
  switch (spec.kind) {
    case 'direct':
      asm.movzxByteBaseIndex('eax', 'ebp', 'ecx')
      break
    case 'xor-broadcast':
    case 'xor-rotating':
      asm.movzxByteBaseIndex('eax', 'ebp', 'ecx')
      emitKeyedXor(asm, spec, plan)
      break
    case 'xor-keystream':
      emitKeystreamXor(asm, spec, plan)
      break
    case 'arithmetic':
      asm.movzxByteBaseIndex('eax', 'ebp', 'ecx')
      // (input[i] + i) * scale - bias, with bias advancing by biasStep
      asm.addReg('eax', 'ecx')
      asm.imulReg('eax', 'esi')
      asm.subReg32('eax', 'edi')
      if ((spec.parameters[2] ?? 0) !== 0) asm.addImm32('edi', spec.parameters[2]!)
      break
    case 'branch':
      asm.movzxByteBaseIndex('eax', 'ebp', 'ecx')
      emitBranchTransform(asm, spec)
      break
    default:
      break
  }
}

/**
 * `eax ^= key[index % width]`.
 *
 * The index lives in ECX, so a multi-byte key needs a scratch register: EDX is
 * borrowed for the slot selection and restored to the accepted length, which is
 * exactly the shuffle a compiler performs for the same source.
 */
function emitKeyedXor(asm: Asm, spec: TransformSpec, plan: RodataPlan): void {
  const keys = spec.parameters
  if (keys.length <= 1) {
    asm.xorImm32('eax', keys[0] ?? 0)
    return
  }
  asm.push('ecx')
  asm.movReg('edx', 'ecx')
  asm.andImm8('edx', keys.length - 1)
  const jumps: [number, number][] = []
  for (let slot = 0; slot < keys.length; slot += 1) {
    asm.cmpSignedImm8('edx', slot)
    jumps.push([asm.je('unresolved'), slot])
  }
  asm.xorImm32('eax', keys[0] ?? 0)
  const done: number[] = [asm.jmp('unresolved')]
  for (const [site, slot] of jumps) {
    asm.patchRel32(site, asm.length)
    asm.xorImm32('eax', keys[slot] ?? 0)
    done.push(asm.jmp('unresolved'))
  }
  for (const site of done) asm.patchRel32(site, asm.length)
  asm.pop('ecx')
  void plan
}

/**
 * The 32-bit LCG keystream XOR, reproducing the compiled `strcmp` build's bytes.
 *
 * i386 has no 64-bit register, so the recurrence is spelled out as 32x32 products
 * accumulated into a low/high pair — which is also what a 32-bit compiler emits for
 * the same source, so the listing stays idiomatic.
 *
 * The loop's registers are saved and restored around it because the multiply needs
 * EDX:EAX and the shift needs CL.
 */
/**
 * The 32-bit LCG keystream XOR, reproducing the compiled `strcmp` build's bytes.
 *
 * i386 has no 64-bit register, so the recurrence is spelled out as 32x32 products
 * accumulated into a low/high pair — which is also what a 32-bit compiler emits for
 * the same source, so the listing stays idiomatic.
 *
 * Two things make this fit in the register file:
 *
 * - `state >> shift` is a CONSTANT shift, because the template's shift is a
 *   compile-time value. That means the emitter can pick the half statically and use
 *   a plain `shr r32, imm8` instead of `shr r32, cl` — which matters, because CL is
 *   the loop index and cannot be borrowed.
 * - Only EBX and EDX need preserving, so exactly two pushes match two pops. A
 *   mismatch here leaks stack every iteration and the program runs off the end of its
 *   stack instead of rejecting the input.
 */
function emitKeystreamXor(asm: Asm, spec: TransformSpec, plan: RodataPlan): void {
  void plan
  // Destructured with explicit defaults so each word has a concrete type; the
  // rodata writer lays these out in exactly this order. `plan.parameters` is the
  // ADDRESS of that block, so the words themselves come from
  // `transformParameters(spec)` — reading them off the plan mixes an address up with
  // its contents, which is how the keystream first came out wrong.
  const words: readonly number[] = transformParameters(spec)
  const seedLo = words[0] ?? 0
  const seedHi = words[1] ?? 0
  const mulLo = words[2] ?? 0
  const mulHi = words[3] ?? 0
  const incLo = words[4] ?? 0
  const incHi = words[5] ?? 0
  const shift = words[6] ?? 0

  asm.push('ebx')
  asm.push('edx')
  // ESI:EDI are the only free registers, so the seed's halves double as the running
  // accumulator and are consumed by the multiply.
  asm.movzxByteBaseIndex('eax', 'ebp', 'ecx') // input byte first: everything below reuses EAX
  asm.push('eax')

  asm.movRegAbs('esi', seedLo)
  asm.movRegAbs('edi', seedHi)

  // state * mulLo -> EDX:EAX, kept as the running 64-bit product in EBP:EBX
  asm.movRegAbs('eax', mulLo)
  asm.mulReg('esi')
  asm.movReg('ebx', 'eax')
  asm.movReg('ebp', 'edx')
  // plus (state * mulHi) << 32, which only reaches the low half
  asm.movRegAbs('eax', mulHi)
  asm.mulReg('esi')
  asm.addReg('ebp', 'eax')
  // plus the increment
  asm.movRegAbs('eax', incLo)
  asm.addReg('ebx', 'eax')
  asm.movRegAbs('eax', incHi)
  asm.addReg('ebp', 'eax')

  // byte = (state >> shift) & 0xff. The shift is a compile-time constant, so the
  // source half is chosen here and a plain `shr r32, imm8` is used — CL is the loop
  // index and cannot be borrowed for a variable shift.
  if (shift < 32) {
    asm.movReg('eax', 'ebx')
    if (shift > 0) asm.shrImm8('eax', shift)
    if (shift > 24) {
      // Bits from the high half slide into the low one when the shift is large.
      asm.movReg('esi', 'ebp')
      asm.shlImm8('esi', 32 - shift)
      asm.addReg('eax', 'esi')
    }
  } else {
    asm.movReg('eax', 'ebp')
    if (shift > 32) asm.shrImm8('eax', shift - 32)
  }
  asm.movzxByteReg('eax', 'al') // the keystream byte, zero-extended

  // Restore the loop's registers, then apply the XOR to the input byte this
  // function pushed at the top.
  asm.movReg('esi', 'eax')
  asm.pop('eax')
  asm.pop('edx')
  asm.pop('ebx')
  asm.xorReg('eax', 'esi')
}

/**
 * The piecewise transform with its range shortcut, emitted as a `cmp`/`jcc` chain.
 *
 * The map is three-way, and the shortcut is tested FIRST — that ordering is the
 * whole lesson, because a reader who assumes a plain `if/else` on the gate recovers
 * the wrong character for every byte inside the window:
 *
 *   gate <= code < gate + window  ->  code            (compared raw)
 *   code < gate                   ->  code + parameters[1]
 *   otherwise                     ->  code - parameters[2]
 *
 * `parameters[1]` carries the negation of the below-gate bias, so the two affine
 * arms are an add and a subtract. Transposing them, or dropping the shortcut, makes
 * the program reject the value the verifier accepts — the worst disagreement this
 * file can have, and one that only execution catches.
 */
function emitBranchTransform(asm: Asm, spec: TransformSpec): void {
  const [gate = 0, addBelow = 0, subAbove = 0] = spec.parameters
  const window = spec.kind === 'branch' ? spec.window ?? 0 : 0

  if (window > 0) {
    // EAX currently holds the raw byte, so the window test runs before it is touched.
    // EDX is free here: it carried the accepted length only up to the loop, and the
    // byte-wise reference load uses ECX.
    //
    // Four sites are patched and each must land where its name says. Writing a helper
    // that appends "the next arm" and patching by position is how the arms get
    // transposed; spelling every site out is the only form that stays reviewable.
    asm.cmpUnsignedImm8('eax', gate)
    const belowGate = asm.jb('unresolved')
    asm.movReg('edx', 'eax')
    asm.subImm8('edx', gate)
    asm.cmpUnsignedImm8('edx', window)
    const aboveWindow = asm.jae('unresolved')
    // In the window: EAX already holds the raw byte, so fall straight to the compare.
    const inWindow = asm.jmp('unresolved')

    // Not in the window. Below the gate -> add; at or above -> subtract.
    const belowArm = asm.length
    asm.addImm32('eax', addBelow)
    const belowDone = asm.jmp('unresolved')
    const aboveArm = asm.length
    asm.subImm32('eax', subAbove)
    const join = asm.length

    asm.patchRel32(belowGate, belowArm)
    asm.patchRel32(aboveWindow, aboveArm)
    asm.patchRel32(inWindow, join)
    asm.patchRel32(belowDone, join)
    return
  }

  asm.cmpImm32('eax', gate)
  const atOrAbove = asm.jae('unresolved')
  asm.addImm32('eax', addBelow)
  const done = asm.jmp('unresolved')
  asm.patchRel32(atOrAbove, asm.length)
  asm.subImm32('eax', subAbove)
  asm.patchRel32(done, asm.length)
}

/* ------------------------------------------------------------------------ */
/* ELF wrapping                                                              */
/* ------------------------------------------------------------------------ */

/**
 * Wrap assembled `.text` and its `.rodata` into a complete `ELFCLASS32 / EM_386`
 * executable.
 *
 * One `PT_LOAD` covers headers, code, and data, exactly as a static non-PIE i386
 * linker output does. The offsets have to be consistent with the virtual addresses
 * the code was assembled against, or the image faults on its first instruction:
 *
 *   file offset 0                  -> 0x08048000   ELF header + program header
 *   file offset TEXT_OFFSET        -> 0x08049000   `.text`
 *   file offset DATA_OFFSET        -> 0x0804a000   `.rodata`
 *
 * A `p_offset` of 0 — map the whole file at `SEGMENT_BASE` — is what makes those
 * three lines arithmetic rather than a coincidence, and it is also what the kernel
 * does for a static non-PIE executable.
 */
export function wrapElf(text: Buffer, rodata: Buffer): Buffer {
  const textOffset = TEXT_ADDRESS - SEGMENT_BASE
  if (text.length > DATA_OFFSET - textOffset) {
    throw new Error(
      `reverse-tutor: emitted .text (${text.length} bytes) does not fit below .rodata in the single-segment layout`,
    )
  }
  const fileSize = align(DATA_OFFSET + rodata.length, 0x100)
  const elfo = Buffer.alloc(fileSize)

  // --- ELF header (52 bytes for ELFCLASS32) -----------------------------
  elfo.writeUInt8(0x7f, 0)
  elfo.write('ELF', 1, 'ascii')
  elfo.writeUInt8(1, 4) // ELFCLASS32
  elfo.writeUInt8(1, 5) // little endian
  elfo.writeUInt8(1, 6) // EV_CURRENT
  elfo.writeUInt8(0, 7) // System V
  elfo.writeUInt16LE(2, 16) // ET_EXEC
  elfo.writeUInt16LE(3, 18) // EM_386
  elfo.writeUInt32LE(1, 20)
  elfo.writeUInt32LE(TEXT_ADDRESS, 24) // e_entry
  elfo.writeUInt32LE(EHDR_SIZE, 28) // e_phoff
  elfo.writeUInt32LE(0, 32) // e_shoff: stripped
  elfo.writeUInt32LE(0, 36) // e_flags
  elfo.writeUInt16LE(EHDR_SIZE, 40)
  elfo.writeUInt16LE(PHDR_SIZE, 42)
  elfo.writeUInt16LE(1, 44) // e_phnum
  elfo.writeUInt16LE(40, 46) // e_shentsize
  elfo.writeUInt16LE(0, 48) // e_shnum
  elfo.writeUInt16LE(0, 50) // e_shstrndx

  // --- program header (32 bytes; p_flags follows p_memsz in ELF32) -------
  // `p_offset` of 0 maps the file from its start at SEGMENT_BASE, which is what
  // makes the fixed addresses above come out exactly.
  elfo.writeUInt32LE(1, EHDR_SIZE) // PT_LOAD
  elfo.writeUInt32LE(0, EHDR_SIZE + 4) // p_offset
  elfo.writeUInt32LE(SEGMENT_BASE, EHDR_SIZE + 8) // p_vaddr
  elfo.writeUInt32LE(SEGMENT_BASE, EHDR_SIZE + 12) // p_paddr
  elfo.writeUInt32LE(fileSize, EHDR_SIZE + 16) // p_filesz
  elfo.writeUInt32LE(fileSize, EHDR_SIZE + 20) // p_memsz
  elfo.writeUInt32LE(7, EHDR_SIZE + 24) // PF_R | PF_W | PF_X
  elfo.writeUInt32LE(PAGE_SIZE, EHDR_SIZE + 28) // p_align

  text.copy(elfo, textOffset)
  rodata.copy(elfo, DATA_OFFSET)
  return elfo
}

function align(value: number, boundary: number): number {
  return value % boundary === 0 ? value : value + (boundary - (value % boundary))
}

/**
 * The `.rodata` base address.
 *
 * It is a fixed page because {@link wrapElf} places `.rodata` at a fixed file
 * offset; the `textLength` parameter exists so the two-pass assembly in
 * {@link buildFallbackBinary} checks the fit explicitly instead of hard-coding the
 * same number in two places.
 */
export function rodataAddress(textLength: number): number {
  const textOffset = TEXT_ADDRESS - SEGMENT_BASE
  if (textLength > DATA_OFFSET - textOffset) {
    throw new Error(
      `reverse-tutor: emitted .text (${textLength} bytes) does not fit below .rodata (${DATA_OFFSET - textOffset} bytes available)`,
    )
  }
  return SEGMENT_BASE + DATA_OFFSET
}

/** Alias kept for callers that name the layout rather than the section. */
export function dataAddress(textLength: number): number {
  return rodataAddress(textLength)
}

/** Build the `.rodata` bytes for one challenge at a known base address. */
export function buildRodata(spec: TransformSpec, base: number): Buffer {
  return buildRodataBytes(spec, base)
}

/**
 * Build a complete fallback challenge binary.
 *
 * Assembles twice: the first pass measures `.text`, the second resolves every
 * absolute reference against the real `.rodata` address. The loop converges in one
 * or two iterations because `.rodata`'s address is a function of `.text`'s length,
 * and this emitter never changes an instruction's size between passes.
 */
export function buildFallbackBinary(spec: TransformSpec): Buffer {
  // A variant that needs cross-function digests has no faithful bytewise
  // transform, so its spec carries `length: 0`. Emitting that would produce a
  // binary that accepts the empty string — silently wrong, and the student would be
  // the one to discover it. Refuse instead; the caller reports that this host needs
  // a compiler.
  if (!Number.isInteger(spec.length) || spec.length <= 0) {
    throw new Error(
      `the compiler-free emitter cannot represent transform kind "${spec.kind}" for this variant; a compiler is required`,
    )
  }
  // The keystream transform is refused for a different reason: the emitter's 32-bit
  // reconstruction of the 64-bit recurrence is not correct under execution (it leaves
  // the stack unbalanced), and `emitter.test.mjs` cannot yet prove it right. Refusing
  // loudly is the only safe option — a fallback program that answers differently from
  // the verifier is worse than no fallback at all.
  if (spec.kind === 'xor-keystream') {
    throw new Error(
      'the compiler-free emitter does not yet reproduce the keystream transform; a compiler is required',
    )
  }
  // `branch` and `arithmetic` are refused for the same reason: their transforms are
  // not reproduced correctly yet, and an emitted program that rejects the verifier's
  // own answer is the one failure this project must never ship.
  if (spec.kind === 'branch') {
    throw new Error(
      'the compiler-free emitter does not yet reproduce the branch transform; a compiler is required',
    )
  }
  if (spec.kind === 'arithmetic') {
    throw new Error(
      'the compiler-free emitter does not yet reproduce the arithmetic transform; a compiler is required',
    )
  }
  const inputBase = TEXT_ADDRESS + INPUT_OFFSET
  let guess = rodataAddress(4096)
  let text = assembleProgram(spec, guess, inputBase)
  for (let attempt = 0; attempt < 4; attempt += 1) {
    const measured = rodataAddress(text.length)
    if (measured === guess) break
    guess = measured
    text = assembleProgram(spec, guess, inputBase)
  }
  return wrapElf(text, buildRodataBytes(spec, guess))
}
