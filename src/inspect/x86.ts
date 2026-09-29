/**
 * A small x86 disassembler for **32-bit** challenge code.
 *
 * The target is i386 because that is what the student's `ida.exe` loads, so this
 * decoder's default bitness is 32. In 32-bit mode there is no REX prefix, the
 * default operand size is 32 bits, the default address size is 32 bits, and the
 * index registers are named `eax`â€¦`edi` â€?the register tables below carry the
 * 16-bit and 8-bit names an operand-size prefix selects.
 *
 * This is an inspection aid, not a disassembler replacement: the student's own IDA
 * Pro is the reference, and `llvm-objdump` is used when the host has one. It exists
 * so `reverse_inspect("objdump")` still works on a host without binutils and so
 * output can be filtered to one function instead of dumping a whole section into
 * the model's context.
 *
 * Coverage is the integer subset a freestanding challenge actually uses: moves,
 * `movsx`/`movzx`, arithmetic, comparisons, `imul`/`idiv` with `cdq`, branches,
 * `lea`, shifts, `int 0x80`, and the prologue/epilogue forms. Anything unrecognised
 * is emitted as `db 0x..` rather than guessed at, because a wrong mnemonic would
 * actively mislead a student.
 *
 * @module dsh-reverse-tutor/inspect/x86
 */

/** Which instruction encoding to decode. */
export type Bitness = 32 | 64

/** One decoded instruction. */
export interface Instruction {
  readonly address: number
  readonly bytes: number[]
  readonly mnemonic: string
  readonly operands: string
  readonly length: number
}

const REG64 = ['rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15']
const REG32 = ['eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi', 'r8d', 'r9d', 'r10d', 'r11d', 'r12d', 'r13d', 'r14d', 'r15d']
const REG16 = ['ax', 'cx', 'dx', 'bx', 'sp', 'bp', 'si', 'di', 'r8w', 'r9w', 'r10w', 'r11w', 'r12w', 'r13w', 'r14w', 'r15w']
const REG8 = ['al', 'cl', 'dl', 'bl', 'spl', 'bpl', 'sil', 'dil', 'r8b', 'r9b', 'r10b', 'r11b', 'r12b', 'r13b', 'r14b', 'r15b']
/** 8-bit encodings 4..7 without a REX prefix name the high bytes, not spl/bpl/sil/dil. */
const REG8_LEGACY = ['al', 'cl', 'dl', 'bl', 'ah', 'ch', 'dh', 'bh', 'r8b', 'r9b', 'r10b', 'r11b', 'r12b', 'r13b', 'r14b', 'r15b']

/** The 32-bit register file, indexed by encoding 0..7. */
const REG32_LEGACY = REG32.slice(0, 8)
const REG16_LEGACY = REG16.slice(0, 8)
const REG8_LEGACY_ONLY = REG8_LEGACY.slice(0, 8)

interface Tables {
  readonly reg: readonly string[]
  readonly suffix: string
  readonly size: number
}

function tableFor(operandSize: number, rexW: boolean, hasRex: boolean, bitness: Bitness): Tables {
  // REX.W does not exist in 32-bit mode; ignoring it there would silently widen
  // every operand of a 32-bit listing.
  if (rexW && bitness === 64) return { reg: REG64, suffix: 'q', size: 8 }
  const wide = bitness === 64
  switch (operandSize) {
    case 0:
      // `ah`/`ch`/`dh`/`bh` without a REX prefix, `spl`/`bpl`/`sil`/`dil` with one.
      // In 32-bit mode there is no REX, so the legacy names always apply.
      if (!wide || !hasRex) return { reg: REG8_LEGACY_ONLY, suffix: 'b', size: 1 }
      return { reg: REG8, suffix: 'b', size: 1 }
    case 1:
      return { reg: wide ? REG16 : REG16_LEGACY, suffix: 'w', size: 2 }
    default:
      return { reg: wide ? REG32 : REG32_LEGACY, suffix: 'l', size: 4 }
  }
}

/** Decode one instruction starting at `bytes[0]`. */
export function decodeInstruction(bytes: Buffer, address: number, bitness: Bitness = 32): Instruction {
  return new Decoder(bytes, address, bitness).decode()
}

class Decoder {
  private index = 0
  private operandSize = 2
  private rexW = false
  private rexR = 0
  private rexX = 0
  private rexB = 0
  /**
   * Whether any REX prefix was present. This matters for 8-bit operands: without
   * REX, encodings 4..7 of an 8-bit register are `ah`/`ch`/`dh`/`bh`, and only a
   * REX prefix makes them `spl`/`bpl`/`sil`/`dil` â€?the low byte of rsp/rbp/rsi/rdi
   * that this toolchain's generated code uses. `34 80` is `xor al, 0x80`
   * (2 bytes); decoding it as a 32-bit form makes it 5 bytes and desynchronises
   * everything after it.
   */
  private hasRex = false
  private lockPrefix = false
  private repPrefix = ''

  constructor(
    private readonly bytes: Buffer,
    private readonly address: number,
    private readonly bitness: Bitness = 32,
  ) {}

  decode(): Instruction {
    this.readPrefixes()
    const opcode = this.byte()
    // The opcode handler is what consumes ModR/M bytes, displacements, and
    // immediates, so the instruction's length is only known AFTER it returns.
    // Reading `this.index` before the call under-counts every instruction that has
    // an operand â€?which is most of them â€?and desynchronises the listing.
    const decoded = this.decodeOpcode(opcode)
    const length = this.index
    return {
      address: this.address,
      bytes: [...this.bytes.subarray(0, length)],
      mnemonic: decoded.mnemonic,
      operands: decoded.operands,
      length: Math.max(1, length),
    }
  }

  private readPrefixes(): void {
    for (;;) {
      const byte = this.peek()
      if (byte === undefined) return
      if (byte === 0xf0) {
        this.lockPrefix = true
        this.index += 1
        continue
      }
      if (byte === 0x66) {
        this.operandSize = 1
        this.index += 1
        continue
      }
      if (byte === 0x67) {
        // Address-size override. In 32-bit mode the default address size is already
        // what challenges use, so this is recorded and skipped rather than acted
        // on; only a 16-bit addressing form would need more, and the templates
        // never emit one.
        this.index += 1
        continue
      }
      if (byte === 0xf2 || byte === 0xf3) {
        this.repPrefix = byte === 0xf3 ? 'rep ' : 'repne '
        this.index += 1
        continue
      }
      if (this.bitness === 64 && byte >= 0x40 && byte <= 0x4f) {
        // REX exists only in 64-bit mode. In 32-bit mode 0x40-0x4f are `inc`/`dec`
        // of EAX..EDI, so consuming them here would eat two instructions' worth of
        // bytes and desynchronise the entire listing.
        this.hasRex = true
        this.rexW = (byte & 8) !== 0
        this.rexR = (byte & 4) !== 0 ? 1 : 0
        this.rexX = (byte & 2) !== 0 ? 1 : 0
        this.rexB = (byte & 1) !== 0 ? 1 : 0
        this.index += 1
        continue
      }
      return
    }
  }

  private tables(): Tables {
    return tableFor(this.operandSize, this.rexW, this.hasRex, this.bitness)
  }

  /**
   * Name the general-purpose register at `index` for the current operand width.
   *
   * One helper instead of a scattered `rexW ? 64-bit : tables.reg` in every opcode,
   * because in 32-bit mode REX.W never applies and the 32-bit table is the only
   * correct answer.
   */
  private accWidth(index: number, tables: Tables): string {
    if (this.rexW && this.bitness === 64) return REG64[index] ?? `r${index}`
    return tables.reg[index] ?? `reg${index}`
  }

  /**
   * The `b`/`w`/`l` suffix an ALU mnemonic carries.
   *
   * In a 32-bit listing IDA â€?and `llvm-objdump --x86-asm-syntax=intel` â€?write both
   * the memory form and the register form without a suffix:
   *
   *   sub   esp, 0x110        (81 ec 10 01 00 00)
   *   add   eax, 0x1          (83 c0 01)
   *   xor   ecx, ecx          (31 c9)
   *   mov   dword ptr [esp], eax
   *
   * The width is never actually ambiguous: a memory operand states it, an immediate
   * form is decided by the opcode, and a register names its own width. Adding `l`
   * where the student's own tooling omits it makes them re-translate every line
   * instead of reading it, which is the one thing a teaching listing must not do.
   */
  private aluSuffix(): string {
    return ''
  }

  private prefixText(): string {
    return `${this.lockPrefix ? 'lock ' : ''}${this.repPrefix}`
  }

  private peek(): number | undefined {
    return this.bytes[this.index]
  }

  private byte(): number {
    const value = this.bytes[this.index]
    this.index += 1
    return value ?? 0
  }

  private imm(size: number): number {
    let value = 0
    for (let offset = 0; offset < size; offset += 1) {
      value |= (this.byte() & 0xff) << (offset * 8)
    }
    return value >>> 0
  }

  private signed(size: number): number {
    // Read the raw little-endian value directly: `imm()` shifts by `offset * 8`,
    // which overflows JavaScript's 32-bit bitwise range for a 4-byte read and
    // would silently produce a wrong displacement (a negative `[rbp-0x110]` came
    // out as a huge positive one before this).
    let value = 0
    let multiplier = 1
    for (let offset = 0; offset < size; offset += 1) {
      value += (this.byte() & 0xff) * multiplier
      multiplier *= 256
    }
    const bits = size * 8
    const limit = 2 ** bits
    return value >= limit / 2 ? value - limit : value
  }

  private hex(value: number, size = 0): string {
    const text = `0x${(value >>> 0).toString(16)}`
    return size > 0 ? `0x${(value >>> 0).toString(16).padStart(size * 2, '0')}` : text
  }

  /**
   * Decode a ModR/M operand pair.
   *
   * `operandSize` overrides the memory operand's printed width for the encodings
   * whose source width differs from the instruction's operand width (`movzx`,
   * `movsx`), where naming the source with the destination's width would be
   * actively misleading.
   */
  private modrm(
    tables: Tables,
    operandSize?: 'byte' | 'word' | 'dword' | 'qword',
  ): { rm: string; reg: string; regIndex: number; isRegister: boolean; rmIndex: number } {
    const modrm = this.byte()
    const mod = (modrm >> 6) & 3
    const regIndex = (((modrm >> 3) & 7) | (this.rexR << 3))
    const rmIndex = ((modrm & 7) | (this.rexB << 3))
    const reg = this.accWidth(regIndex, tables)
    if (mod === 3) {
      return { rm: this.accWidth(rmIndex, tables), reg, regIndex, rmIndex, isRegister: true }
    }

    // The memory operand carries its own size word, always. That is how LLVM and
    // IDA print it in 32-bit code (`mov dword ptr [ebp - 0x4], 0x2`), and it is
    // the only thing that tells a reader how wide the access is when the other
    // operand is an immediate.
    const natural = this.rexW && this.bitness === 64 ? 'qword' : tables.size === 1 ? 'byte' : tables.size === 2 ? 'word' : 'dword'
    const width = operandSize ?? natural
    const sizeWord = `${width} ptr `
    let base: string
    let index: string | undefined
    let scale = 1
    let displacement = 0
    let hasDisplacement = false

    if ((modrm & 7) === 4) {
      const sib = this.byte()
      scale = 1 << ((sib >> 6) & 3)
      const indexIndex = ((sib >> 3) & 7) | (this.rexX << 3)
      const baseIndex = (sib & 7) | (this.rexB << 3)
      index = indexIndex === 4 ? undefined : (this.bitness === 64 ? REG64[indexIndex]! : REG32_LEGACY[indexIndex & 7]!)
      base = baseIndex === 5 && mod === 0 ? '' : (this.bitness === 64 ? REG64[baseIndex]! : REG32_LEGACY[baseIndex & 7]!)
      if (base === '') {
        displacement = this.signed(4)
        hasDisplacement = true
      }
    } else if ((modrm & 7) === 5 && mod === 0) {
      base = ''
      displacement = this.signed(4)
      hasDisplacement = true
    } else {
      base = this.bitness === 64 ? REG64[(modrm & 7) | (this.rexB << 3)]! : REG32_LEGACY[modrm & 7]!
    }

    if (mod === 1) {
      displacement = this.signed(1)
      hasDisplacement = true
    } else if (mod === 2) {
      displacement = this.signed(4)
      hasDisplacement = true
    }

    // Build `base + index*scale Â± disp`, matching the spacing LLVM and IDA use in
    // 32-bit listings: a displacement is always spaced (`[ebp - 0x4]`,
    // `[ebp + 0x8]`), and components are joined explicitly â€?concatenating them
    // would render `[eax+ecx]` as the nonexistent register `[eawecx]`.
    const head: string[] = []
    if (base !== '') head.push(base)
    if (index !== undefined) head.push(scale === 1 ? index : `${index}*${scale}`)
    const dispText = hasDisplacement
      ? ` ${displacement < 0 ? '-' : '+'} ${this.hex(Math.abs(displacement))}`
      : ''
    const inner = `${head.join(' + ')}${dispText}`
    return { rm: `${sizeWord}[${inner}]`, reg, regIndex, rmIndex, isRegister: false }
  }

  private decodeOpcode(opcode: number): { mnemonic: string; operands: string } {
    const tables = this.tables()
    // Immediate width is NOT the operand width. With REX.W an operand is 64 bits
    // but every immediate except `mov r64, imm64` is still 32 bits (sign-extended
    // at execution); reading 8 bytes here would silently swallow the next
    // instruction and desynchronise the whole listing.
    const immSize = this.operandSize === 0 ? 1 : this.operandSize === 1 ? 2 : 4
    const suffix = this.rexW && this.bitness === 64 ? '' : tables.suffix
    const prefix = this.prefixText()

    switch (opcode) {
      case 0x90:
        return { mnemonic: `${prefix}nop`, operands: '' }
      case 0xc3:
        return { mnemonic: `${prefix}ret`, operands: '' }
      case 0xc9:
        return { mnemonic: 'leave', operands: '' }
      case 0xcc:
        return { mnemonic: 'int3', operands: '' }
      case 0xcd: {
        // `int imm8`. In 32-bit Linux this is how every kernel call is made:
        // `int 0x80` with the syscall number in EAX. It is the single most
        // important instruction for a student to recognise here.
        const vector = this.byte()
        return { mnemonic: 'int', operands: this.hex(vector) }
      }
      case 0xf4:
        return { mnemonic: 'hlt', operands: '' }
      case 0xf8:
        return { mnemonic: 'clc', operands: '' }
      case 0xf9:
        return { mnemonic: 'stc', operands: '' }
      case 0xfc:
        return { mnemonic: 'cld', operands: '' }
      case 0xfd:
        return { mnemonic: 'std', operands: '' }
      // Sign-extension conversions. GCC emits `cdq` before a 32-bit `idiv`, and
      // `cqo` before a 64-bit one, so both turn up in ordinary challenge code.
      case 0x98:
        return { mnemonic: this.rexW ? 'cdqe' : 'cwde', operands: '' }
      case 0x99:
        return { mnemonic: this.rexW ? 'cqo' : 'cdq', operands: '' }
      case 0x0f:
        return this.decodeTwoByte()
      default:
        break
    }

    // 0x50-0x57 push r64 / 0x58-0x5f pop r64
    if (opcode >= 0x50 && opcode <= 0x57) {
      return { mnemonic: 'push', operands: this.accWidth(opcode - 0x50 + this.rexB * 8, tables) }
    }
    if (opcode >= 0x58 && opcode <= 0x5f) {
      return { mnemonic: 'pop', operands: this.accWidth(opcode - 0x58 + this.rexB * 8, tables) }
    }
    // 0xb8-0xbf mov r, imm
    if (opcode >= 0xb8 && opcode <= 0xbf) {
      const register = this.accWidth(opcode - 0xb8 + this.rexB * 8, tables)
      const immediate = this.rexW ? this.imm(8) : this.imm(immSize)
      return { mnemonic: 'mov', operands: `${register}, ${this.hex(immediate)}` }
    }
    // 0x91-0x97 xchg eax, r
    if (opcode >= 0x91 && opcode <= 0x97) {
      const other = this.accWidth(opcode - 0x90 + this.rexB * 8, tables)
      return { mnemonic: 'xchg', operands: `${this.rexW ? 'rax' : 'eax'}, ${other}` }
    }
    // 0x68/0x6a push imm
    if (opcode === 0x68) return { mnemonic: 'push', operands: this.hex(this.signed(4)) }
    if (opcode === 0x6a) return { mnemonic: 'push', operands: this.hex(this.signed(1)) }

    // 0x40-0x47 / 0x48-0x4f: `inc`/`dec r32` in 32-bit mode. Only reachable here
    // because `readPrefixes` consumes those bytes as REX in 64-bit mode instead.
    if (this.bitness === 32 && opcode >= 0x40 && opcode <= 0x4f) {
      const name = this.accWidth(opcode & 7, tables)
      return { mnemonic: opcode < 0x48 ? 'inc' : 'dec', operands: name }
    }

    // 0x63 movsxd: sign-extend a 32-bit source into a 64-bit register, which only
    // exists in 64-bit mode. In 32-bit mode 0x63 is `arpl`.
    if (opcode === 0x63 && this.bitness === 64) {
      const operand = this.modrm(tables, 'dword')
      const register = this.accWidth(operand.regIndex, tables)
      return { mnemonic: `${prefix}movsxd`, operands: `${register}, ${operand.rm}` }
    }

    // Group 1 with an 8-bit immediate: same encoding as 0x80/0x81 at 0x82/0x83,
    // already handled above. 0x84/0x85 (test) follow.

    // Group 1: 0x80..0x83 arithmetic with immediate
    if (opcode >= 0x80 && opcode <= 0x83) {
      const names = ['add', 'or', 'adc', 'sbb', 'and', 'sub', 'xor', 'cmp']
      const operand = this.modrm(tables)
      const immediateSize = opcode === 0x80 || opcode === 0x83 ? 1 : immSize
      const immediate = opcode === 0x83 ? this.signed(1) : this.imm(immediateSize)
      const mnemonic = `${prefix}${names[operand.regIndex & 7]}${this.aluSuffix()}`
      return { mnemonic, operands: `${operand.rm}, ${this.hex(immediate)}` }
    }

    // Group 2/3/4/5 and the common two-operand forms.
    const binary: Record<number, string> = {
      0x00: 'add', 0x01: 'add', 0x02: 'add', 0x03: 'add',
      0x08: 'or', 0x09: 'or', 0x0a: 'or', 0x0b: 'or',
      0x10: 'adc', 0x11: 'adc', 0x12: 'adc', 0x13: 'adc',
      0x18: 'sbb', 0x19: 'sbb', 0x1a: 'sbb', 0x1b: 'sbb',
      0x20: 'and', 0x21: 'and', 0x22: 'and', 0x23: 'and',
      0x28: 'sub', 0x29: 'sub', 0x2a: 'sub', 0x2b: 'sub',
      0x30: 'xor', 0x31: 'xor', 0x32: 'xor', 0x33: 'xor',
      0x38: 'cmp', 0x39: 'cmp', 0x3a: 'cmp', 0x3b: 'cmp',
      0x84: 'test', 0x85: 'test',
      0x86: 'xchg', 0x87: 'xchg',
      0x88: 'mov', 0x89: 'mov', 0x8a: 'mov', 0x8b: 'mov',
    }
    const mnemonicBase = binary[opcode]
    if (mnemonicBase !== undefined) {
      const operand = this.modrm(tables)
      // In x86 these forms always encode the register operand in ModR/M.reg and
      // the r/m operand in ModR/M.r/m. The TEXTUAL order follows bit 1 of the
      // opcode:
      //   0x00 (bit 1 clear) -> `add r/m, reg`   (ModR/M.reg is the source)
      //   0x02 (bit 1 set)   -> `add reg, r/m`   (ModR/M.reg is the destination)
      // So `89 /r` prints as `mov r/m, reg` and `8b /r` as `mov reg, r/m`.
      // Writing this backwards yields a syntactically valid, semantically
      // reversed instruction â€?the worst possible failure for a teaching tool.
      const regFirst = (opcode & 2) !== 0
      const register = this.accWidth(operand.regIndex, tables)
      const text = `${mnemonicBase}${this.aluSuffix()}`
      // Both operands already carry their own width from `modrm()`.
      return {
        mnemonic: `${prefix}${text}`,
        operands: regFirst ? `${register}, ${operand.rm}` : `${operand.rm}, ${register}`,
      }
    }

    // Group 11: mov r/m, imm (0xc6/0xc7)
    if (opcode === 0xc6 || opcode === 0xc7) {
      const operand = this.modrm(tables)
      const immediate = this.imm(opcode === 0xc6 ? 1 : immSize)
      return {
        mnemonic: `${prefix}mov${this.aluSuffix()}`,
        operands: `${operand.rm}, ${this.hex(immediate)}`,
      }
    }

    // Shifts: 0xc0/0xc1/0xd0-0xd3
    if (opcode === 0xc0 || opcode === 0xc1) {
      const names = ['rol', 'ror', 'rcl', 'rcr', 'shl', 'shr', 'sal', 'sar']
      const operand = this.modrm(tables)
      const immediate = this.imm(1)
      return {
        mnemonic: `${prefix}${names[operand.regIndex & 7]}${this.aluSuffix()}`,
        operands: `${operand.rm}, ${this.hex(immediate)}`,
      }
    }

    // Unary group 3: 0xf6/0xf7
    if (opcode === 0xf6 || opcode === 0xf7) {
      const names = ['test', 'test', 'not', 'neg', 'mul', 'imul', 'div', 'idiv']
      const operand = this.modrm(tables)
      const name = names[operand.regIndex & 7]!
      if (name === 'test') {
        const immediate = this.imm(opcode === 0xf6 ? 1 : immSize)
        return { mnemonic: `${prefix}test`, operands: `${operand.rm}, ${this.hex(immediate)}` }
      }
      return { mnemonic: `${prefix}${name}${this.rexW ? '' : suffix}`, operands: operand.rm }
    }

    // Unary group 5: 0xfe/0xff
    if (opcode === 0xfe || opcode === 0xff) {
      const names = ['inc', 'dec', 'call', 'callf', 'jmp', 'jmpf', 'push', 'invalid']
      const operand = this.modrm(tables)
      const name = names[operand.regIndex & 7]!
      if (name.startsWith('jmp') || name.startsWith('call')) {
        return { mnemonic: `${prefix}${name.replace('f', ' far')}`, operands: operand.rm }
      }
      return { mnemonic: `${prefix}${name}${this.rexW ? '' : suffix}`, operands: operand.rm }
    }

    // Group 1 with accumulator immediates: 0x04..0x3d step 8, plus 0xa8/0xa9
    if ((opcode & 0xc7) === 0x04) {
      const names = ['add', 'or', 'adc', 'sbb', 'and', 'sub', 'xor', 'cmp']
      const name = names[(opcode >> 3) & 7]!
      const immediate = this.imm(immSize)
      return { mnemonic: `${prefix}${name}${this.rexW ? '' : suffix}`, operands: `${this.rexW ? 'rax' : 'eax'}, ${this.hex(immediate)}` }
    }
    if (opcode === 0xa8 || opcode === 0xa9) {
      const immediate = this.imm(opcode === 0xa8 ? 1 : immSize)
      return { mnemonic: `${prefix}test`, operands: `${this.rexW ? 'rax' : 'eax'}, ${this.hex(immediate)}` }
    }

    // Short jumps and calls
    if (opcode >= 0x70 && opcode <= 0x7f) {
      const names = ['jo', 'jno', 'jb', 'jae', 'je', 'jne', 'jbe', 'ja', 'js', 'jns', 'jp', 'jnp', 'jl', 'jge', 'jle', 'jg']
      const displacement = this.signed(1)
      const target = this.address + this.index + displacement
      return { mnemonic: `${prefix}${names[opcode - 0x70]}`, operands: this.hex(target) }
    }
    if (opcode === 0xeb) {
      const displacement = this.signed(1)
      return { mnemonic: `${prefix}jmp`, operands: this.hex(this.address + this.index + displacement) }
    }
    if (opcode === 0xe9) {
      const displacement = this.signed(4)
      return { mnemonic: `${prefix}jmp`, operands: this.hex(this.address + this.index + displacement) }
    }
    if (opcode === 0xe8) {
      const displacement = this.signed(4)
      return { mnemonic: `${prefix}call`, operands: this.hex(this.address + this.index + displacement) }
    }

    // lea
    if (opcode === 0x8d) {
      const operand = this.modrm(tables)
      const register = this.accWidth(operand.regIndex, tables)
      // `lea` keeps the memory operand's syntax but never the size word.
      return { mnemonic: `${prefix}lea`, operands: `${register}, ${operand.rm.replace(/(byte|word|dword|qword) ptr /, '')}` }
    }

    return { mnemonic: 'db', operands: `0x${opcode.toString(16).padStart(2, '0')}` }
  }

  private decodeTwoByte(): { mnemonic: string; operands: string } {
    const tables = this.tables()
    const prefix = this.prefixText()
    const opcode2 = this.byte()

    switch (opcode2) {
      case 0x05:
        // `syscall` exists only in 64-bit mode; in 32-bit mode 0F 05 is `sysenter`,
        // which is not how these challenges call the kernel (`int 0x80` is).
        return { mnemonic: `${prefix}${this.bitness === 64 ? 'syscall' : 'sysenter'}`, operands: '' }
      case 0x0b:
        return { mnemonic: 'ud2', operands: '' }
      // 0F B6/B7 and 0F BE/BF widen a BYTE or WORD source into the accumulator
      // width. The source size must be named explicitly, or `movzx eax, byte ptr
      // [edx+eax]` would read as a 32-bit load and describe a different program.
      case 0xb6:
      case 0xb7: {
        const operand = this.modrm(tables, opcode2 === 0xb6 ? 'byte' : 'word')
        const register = this.accWidth(operand.regIndex, tables)
        return { mnemonic: `${prefix}movzx`, operands: `${register}, ${operand.rm}` }
      }
      case 0xbe:
      case 0xbf: {
        const operand = this.modrm(tables, opcode2 === 0xbe ? 'byte' : 'word')
        const register = this.accWidth(operand.regIndex, tables)
        return { mnemonic: `${prefix}movsx`, operands: `${register}, ${operand.rm}` }
      }
      case 0xaf: {
        const operand = this.modrm(tables)
        const register = this.accWidth(operand.regIndex, tables)
        return { mnemonic: `${prefix}imul`, operands: `${register}, ${operand.rm}` }
      }
      case 0x1f: {
        const operand = this.modrm(tables)
        return { mnemonic: `${prefix}nop`, operands: operand.rm }
      }
      default:
        break
    }

    if (opcode2 >= 0x80 && opcode2 <= 0x8f) {
      const names = ['jo', 'jno', 'jb', 'jae', 'je', 'jne', 'jbe', 'ja', 'js', 'jns', 'jp', 'jnp', 'jl', 'jge', 'jle', 'jg']
      const displacement = this.signed(4)
      const target = this.address + this.index + displacement
      return { mnemonic: `${prefix}${names[opcode2 - 0x80]}`, operands: this.hex(target) }
    }
    if (opcode2 === 0x90) {
      const operand = this.modrm(tables)
      return { mnemonic: `${prefix}seto`, operands: operand.rm }
    }
    if (opcode2 >= 0x90 && opcode2 <= 0x9f) {
      const names = ['seto', 'setno', 'setb', 'setae', 'sete', 'setne', 'setbe', 'seta', 'sets', 'setns', 'setp', 'setnp', 'setl', 'setge', 'setle', 'setg']
      const operand = this.modrm(tables)
      return { mnemonic: `${prefix}${names[opcode2 - 0x90]}`, operands: operand.rm }
    }
    if (opcode2 >= 0x40 && opcode2 <= 0x4f) {
      const names = ['cmovo', 'cmovno', 'cmovb', 'cmovae', 'cmove', 'cmovne', 'cmovbe', 'cmova', 'cmovs', 'cmovns', 'cmovp', 'cmovnp', 'cmovl', 'cmovge', 'cmovle', 'cmovg']
      const operand = this.modrm(tables)
      const register = this.accWidth(operand.regIndex, tables)
      return { mnemonic: `${prefix}${names[opcode2 - 0x40]}`, operands: `${register}, ${operand.rm}` }
    }
    if (opcode2 === 0xef) return { mnemonic: `${prefix}pxor`, operands: 'xmm, xmm' }

    return { mnemonic: 'db', operands: `0x0f, 0x${opcode2.toString(16).padStart(2, '0')}` }
  }
}

/** Render one instruction the way `objdump -Mintel` does. */
export function formatInstruction(instruction: Instruction): string {
  const address = instruction.address.toString(16).padStart(16, '0')
  const raw = instruction.bytes.map(byte => byte.toString(16).padStart(2, '0')).join(' ')
  const text = instruction.operands === ''
    ? instruction.mnemonic
    : `${instruction.mnemonic.padEnd(8)}${instruction.operands}`
  return `  ${address}:  ${raw.padEnd(24, ' ')} ${text}`
}

/** Decode a straight run of bytes, stopping at `maxInstructions` or a terminal `ret`/`hlt`. */
export function decodeBlock(
  bytes: Buffer,
  address: number,
  options: { readonly maxInstructions?: number; readonly stopAtRet?: boolean } = {},
): Instruction[] {
  const max = options.maxInstructions ?? 400
  const out: Instruction[] = []
  let offset = 0
  while (offset < bytes.length && out.length < max) {
    const instruction = decodeInstruction(bytes.subarray(offset), address + offset)
    out.push(instruction)
    offset += instruction.length
    if (options.stopAtRet !== false && (instruction.mnemonic.endsWith('ret') || instruction.mnemonic === 'hlt')) break
  }
  return out
}

/** Registers written by an instruction, used for a coarse data-flow summary. */
export function writtenRegisters(instruction: Instruction): string[] {
  const mnemonic = instruction.mnemonic.replace(/^(lock |rep |repne )/, '')
  const [first] = instruction.operands.split(',').map(part => part.trim())
  if (first === undefined || first === '') return []
  if (first.includes('[')) return []
  const writes = new Set([
    'mov', 'movzx', 'movsx', 'lea', 'add', 'sub', 'xor', 'and', 'or', 'adc', 'sbb',
    'shl', 'shr', 'sal', 'sar', 'imul', 'inc', 'dec', 'pop', 'sete', 'setne',
  ])
  if (!writes.has(mnemonic)) return []
  return [first]
}
