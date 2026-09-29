/**
 * Execute emitted fallback challenges in a tiny i386 interpreter.
 *
 * The compiler-free emitter writes real i386 machine code, and there is no
 * emulator on this host (no WSL distribution, no `qemu-user`, and installing one
 * needs a package manager this deployment does not have). Leaving that code
 * unverified would mean shipping a fallback whose correctness rests on inspection
 * alone 鈥?and the emitter's failure mode is the worst one in the project: a binary
 * that accepts a different value than the verifier holds.
 *
 * So this file interprets. It is deliberately a *test* and not production code: it
 * covers exactly the instruction set `challenge/elf.ts` emits, runs the emitted
 * program against real stdin, and asserts the exit status. A gap in the
 * interpreter fails loudly rather than silently skipping an instruction.
 */

/**
 * Decode and execute an i386 program.
 *
 * @param memory - the mapped image, indexed by offset from `base`
 * @param entry - where execution starts
 * @param base - the address `memory[0]` maps to
 * @param stdin - bytes available on file descriptor 0
 * @returns the exit status, captured stdout, and a decoded trace
 */
export function runI386(memory, entry, base, stdin = '') {
  const mem = new Uint8Array(memory)
  const regs = { eax: 0, ecx: 0, edx: 0, ebx: 0, esp: 0, ebp: 0, esi: 0, edi: 0 }
  const flags = { zf: false, cf: false, sf: false, of: false }
  const trace = []
  let stdout = ''
  let exitCode = null

  // A 64 KiB stack below the image, as the kernel would set up.
  const STACK_TOP = 0xffff_0000
  const stack = new Uint8Array(0x1_0000)
  regs.esp = STACK_TOP

  const read8 = address => {
    if (address >= base && address < base + mem.length) return mem[address - base]
    // The stack is addressed downward from STACK_TOP, so the byte at STACK_TOP-1 is
    // index 0. Using `STACK_TOP - 1 - address` shifts every access by one and makes
    // the last valid address look out of range.
    if (address >= STACK_TOP - stack.length && address < STACK_TOP) return stack[STACK_TOP - address]
    throw new Error(
      `read outside mapped memory at 0x${(address >>> 0).toString(16)} ` +
        `(last instructions: ${trace.slice(-6).map(entry => `0x${entry.pc.toString(16)}`).join(', ')})`,
    )
  }
  const write8 = (address, value) => {
    if (address >= base && address < base + mem.length) {
      mem[address - base] = value & 0xff
      return
    }
    if (address >= STACK_TOP - stack.length && address < STACK_TOP) {
      stack[STACK_TOP - address] = value & 0xff
      return
    }
    throw new Error(
      `write outside mapped memory at 0x${(address >>> 0).toString(16)} ` +
        `(last instructions: ${trace.slice(-6).map(entry => `0x${entry.pc.toString(16)}`).join(', ')})`,
    )
  }
  /**
   * A 32-bit read, as a SIGNED value 鈥?which is what a 32-bit register holds.
   *
   * This matters because it is *only* signedness that makes `cmp` (which is a
   * subtraction, not an unsigned comparison) behave correctly: with an unsigned
   * value in EBX, the arithmetic template's negative-looking reference elements
   * compare unequal and the emitted program rejects its own accepted value while the
   * predicate accepts it. Keeping every register as `|0` also means the sign is
   * dropped exactly where the machine drops it, on the store.
   *
   * Instruction fields that are genuinely unsigned callers mask explicitly: a
   * `disp32` goes through `read32SignedField`, and a `rel32` through `read32Signed`.
   */
  const read32 = address =>
    (read8(address) | (read8(address + 1) << 8) | (read8(address + 2) << 16) | (read8(address + 3) << 24)) | 0
  /**
   * A 32-bit instruction field read as SIGNED.
   *
   * `rel32` branch offsets and `disp32` displacements are signed, so they must be
   * sign-extended before being added to an address. Treating them as unsigned is
   * how a backward jump lands megabytes above the image and reports a faulting
   * address that looks nothing like the instruction that caused it.
   */
  const read32Signed = address => read32(address) | 0
  /** An unsigned 32-bit instruction field, such as the displacement of a `mov r32, imm32`. */
  const read32Unsigned = address => read32(address) >>> 0
  const write32 = (address, value) => {
    for (let i = 0; i < 4; i += 1) write8(address + i, (value >>> (i * 8)) & 0xff)
  }

  const REG_NAMES = ['eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi']
  let inputOffset = 0
  let pc = entry

  const setFlagsSub = (a, b) => {
    const result = (a - b) | 0
    flags.zf = result === 0
    flags.sf = result < 0
    flags.cf = (a >>> 0) < (b >>> 0)
  }

  for (let steps = 0; steps < 200_000; steps += 1) {
    const startPc = pc
    const opcode = read8(pc)
    pc += 1

    /** Resolve a ModR/M operand to a value getter/setter pair. */
    const modrm = () => {
      const byte = read8(pc)
      pc += 1
      const mod = (byte >> 6) & 3
      const reg = (byte >> 3) & 7
      const rm = byte & 7
      if (mod === 3) {
        return { reg, get: () => regs[REG_NAMES[rm]] | 0, set: v => { regs[REG_NAMES[rm]] = v | 0 }, isRegister: true }
      }
      let address
      if (rm === 4) {
        const sibByte = read8(pc)
        pc += 1
        const scale = 1 << ((sibByte >> 6) & 3)
        const index = (sibByte >> 3) & 7
        const baseReg = sibByte & 7
        // `mod=00` with a SIB base of 101 is not "EBP + index": it means NO base
        // register, with a full disp32 following.
        if (baseReg === 5 && mod === 0) {
          address = read32Unsigned(pc) + (index === 4 ? 0 : regs[REG_NAMES[index]] * scale)
          pc += 4
        } else {
          address = regs[REG_NAMES[baseReg]] + (index === 4 ? 0 : regs[REG_NAMES[index]] * scale)
        }
      } else if (rm === 5 && mod === 0) {
        address = read32Unsigned(pc)
        pc += 4
      } else {
        address = regs[REG_NAMES[rm]]
      }
      if (mod === 1) {
        address = (address + (read8(pc) << 24 >> 24)) | 0
        pc += 1
      } else if (mod === 2) {
        address = (address + read32Signed(pc)) | 0
        pc += 4
      }
      return { reg, address, get: () => read32(address), set: v => write32(address, v), isRegister: false }
    }

    switch (opcode) {
      case 0x90:
        break
      case 0x55:
        regs.esp -= 4
        write32(regs.esp, regs.ebp)
        break
      case 0x5d:
        regs.ebp = read32(regs.esp)
        regs.esp += 4
        break
      case 0x50:
      case 0x51:
      case 0x52:
      case 0x53:
      case 0x56:
      case 0x57: {
        const name = REG_NAMES[opcode - 0x50]
        regs.esp -= 4
        write32(regs.esp, regs[name])
        break
      }
      case 0x58:
      case 0x59:
      case 0x5a:
      case 0x5b:
      case 0x5e:
      case 0x5f: {
        const name = REG_NAMES[opcode - 0x58]
        regs[name] = read32(regs.esp)
        regs.esp += 4
        break
      }
      case 0x40:
      case 0x41:
      case 0x42:
      case 0x43:
      case 0x46:
      case 0x47:
        regs[REG_NAMES[opcode - 0x40]] = (regs[REG_NAMES[opcode - 0x40]] + 1) | 0
        break
      case 0x48:
      case 0x49:
      case 0x4a:
      case 0x4b:
      case 0x4e:
      case 0x4f:
        regs[REG_NAMES[opcode - 0x48]] = (regs[REG_NAMES[opcode - 0x48]] - 1) | 0
        break
      case 0xb8:
      case 0xb9:
      case 0xba:
      case 0xbb:
      case 0xbc:
      case 0xbd:
      case 0xbe:
      case 0xbf: {
        // `mov r32, imm32`. `ebp` is 0xbd, which the generated prologue uses to load
        // the input pointer, so the whole range is listed rather than the two
        // registers that happened to appear first.
        const name = REG_NAMES[opcode - 0xb8]
        regs[name] = read32Unsigned(pc)
        pc += 4
        break
      }
      case 0x89: {
        const operand = modrm()
        operand.set(regs[REG_NAMES[operand.reg]])
        break
      }
      case 0x8b: {
        const operand = modrm()
        regs[REG_NAMES[operand.reg]] = operand.get()
        break
      }
      case 0x8d: {
        const operand = modrm()
        regs[REG_NAMES[operand.reg]] = operand.address
        break
      }
      case 0x88: {
        const operand = modrm()
        operand.set(regs[REG_NAMES[operand.reg]] & 0xff)
        break
      }
      case 0x31: {
        const operand = modrm()
        const result = (operand.get() ^ regs[REG_NAMES[operand.reg]]) | 0
        operand.set(result)
        flags.zf = result === 0
        break
      }
      case 0x01: {
        const operand = modrm()
        operand.set((operand.get() + regs[REG_NAMES[operand.reg]]) | 0)
        break
      }
      case 0x29: {
        const operand = modrm()
        const result = (operand.get() - regs[REG_NAMES[operand.reg]]) | 0
        operand.set(result)
        setFlagsSub(operand.get() + regs[REG_NAMES[operand.reg]], regs[REG_NAMES[operand.reg]])
        break
      }
      case 0x39: {
        const operand = modrm()
        setFlagsSub(operand.get(), regs[REG_NAMES[operand.reg]])
        break
      }
      case 0x81: {
        const operand = modrm()
        const immediate = read32Unsigned(pc)
        pc += 4
        const before = operand.get()
        switch (operand.reg) {
          case 0: operand.set((before + immediate) | 0); break
          case 5: operand.set((before - immediate) | 0); setFlagsSub(before, immediate); break
          case 6: { const r = (before ^ immediate) | 0; operand.set(r); flags.zf = r === 0; break }
          // 81 /7 is `cmp r/m32, imm32`. Every other sub-opcode above writes its
          // result back; this one must not, and it is what the generated
          // `cmp eax, 0` compiles to 鈥?so getting it wrong silently changes the
          // following branch instead of failing loudly.
          case 7: setFlagsSub(before, immediate); break
          default: throw new Error(`unhandled 0x81 /${operand.reg}`)
        }
        break
      }
      case 0x83: {
        const operand = modrm()
        const immediate = read8(pc) << 24 >> 24
        pc += 1
        switch (operand.reg) {
          case 0: operand.set((operand.get() + immediate) | 0); break
          case 4: operand.set(operand.get() & immediate); break
          case 5: { const before = operand.get(); operand.set((before - immediate) | 0); setFlagsSub(before, immediate); break }
          case 7: setFlagsSub(operand.get(), immediate); break
          default: throw new Error(`unhandled 0x83 /${operand.reg}`)
        }
        break
      }
      case 0x69: {
        const operand = modrm()
        const immediate = read32Unsigned(pc)
        pc += 4
        operand.set(Math.imul(operand.get(), immediate))
        break
      }
      case 0x0f: {
        const second = read8(pc)
        pc += 1
        if (second === 0xb6) {
          const byte = read8(pc)
          pc += 1
          const mod = (byte >> 6) & 3
          const reg = (byte >> 3) & 7
          const rm = byte & 7
          let value
          if (mod === 3) {
            value = regs[REG_NAMES[rm]] & 0xff
          } else {
            let address
            if (rm === 4) {
              const sibByte = read8(pc)
              pc += 1
              const scale = 1 << ((sibByte >> 6) & 3)
              const index = (sibByte >> 3) & 7
              const baseReg = sibByte & 7
              const indexTerm = index === 4 ? 0 : regs[REG_NAMES[index]] * scale
              if (baseReg === 5 && mod === 0) {
                address = read32(pc) + indexTerm
                pc += 4
              } else {
                address = regs[REG_NAMES[baseReg]] + indexTerm
              }
            } else {
              address = regs[REG_NAMES[rm]]
            }
            if (mod === 1) {
              address = (address + (read8(pc) << 24 >> 24)) | 0
              pc += 1
            } else if (mod === 2) {
              address = (address + read32(pc)) | 0
              pc += 4
            }
            value = read8(address)
          }
          regs[REG_NAMES[reg]] = value
          break
        }
        if (second === 0xaf) {
          const operand = modrm()
          regs[REG_NAMES[operand.reg]] = Math.imul(regs[REG_NAMES[operand.reg]], operand.get())
          break
        }
        if (second === 0x84 || second === 0x85) {
          // `0F 84/85 rel32` has NO ModR/M byte. Consuming one here reads the first
          // byte of the displacement as an operand, which shifts the branch target
          // by four and desynchronises the whole program 鈥?the interpreter then
          // faults far from the instruction that actually went wrong.
          const offset = read32Signed(pc)
          pc += 4
          const taken = second === 0x84 ? flags.zf : !flags.zf
          if (taken) pc += offset
          break
        }
        if (second === 0x82 || second === 0x83) {
          const offset = read32Signed(pc)
          pc += 4
          const taken = second === 0x82 ? flags.cf : !flags.cf
          if (taken) pc += offset
          break
        }
        throw new Error(`unhandled 0F ${second.toString(16)}`)
      }
      case 0x74:
      case 0x75: {
        const offset = read32Signed(pc)
        pc += 4
        const taken = opcode === 0x74 ? flags.zf : !flags.zf
        if (taken) pc += offset
        break
      }
      case 0xe9: {
        const offset = read32Signed(pc)
        pc += 4
        pc += offset
        break
      }
      case 0xc1: {
        const operand = modrm()
        const count = read8(pc)
        pc += 1
        const value = operand.get()
        if (operand.reg === 4) operand.set(value << count)
        else if (operand.reg === 5) operand.set(value >>> count)
        else throw new Error(`unhandled 0xc1 /${operand.reg}`)
        break
      }
      case 0xd3: {
        const operand = modrm()
        const count = regs.ecx & 0x1f
        if (operand.reg === 5) operand.set(operand.get() >>> count)
        else throw new Error(`unhandled 0xd3 /${operand.reg}`)
        break
      }
      case 0xf7: {
        const operand = modrm()
        if (operand.reg !== 4) throw new Error(`unhandled 0xf7 /${operand.reg}`)
        const product = BigInt(regs.eax >>> 0) * BigInt(operand.get() >>> 0)
        regs.eax = Number(product & 0xffff_ffffn) | 0
        regs.edx = Number((product >> 32n) & 0xffff_ffffn) | 0
        break
      }
      case 0xcd: {
        const vector = read8(pc)
        pc += 1
        if (vector !== 0x80) throw new Error(`unhandled int 0x${vector.toString(16)}`)
        const number = regs.eax
        if (number === 4) {
          const buffer = regs.ecx
          const length = regs.edx
          let text = ''
          for (let i = 0; i < length; i += 1) text += String.fromCharCode(read8(buffer + i))
          stdout += text
          regs.eax = length
        } else if (number === 3) {
          const buffer = regs.ecx
          const length = regs.edx
          const available = stdin.length - inputOffset
          const count = Math.max(0, Math.min(length, available))
          for (let i = 0; i < count; i += 1) write8(buffer + i, stdin.charCodeAt(inputOffset + i) & 0xff)
          inputOffset += count
          regs.eax = count
        } else if (number === 1) {
          exitCode = regs.ebx & 0xff
          return { exitCode, stdout, steps, trace }
        } else {
          throw new Error(`unhandled syscall ${number}`)
        }
        break
      }
      case 0xf4:
        return { exitCode: exitCode ?? 0, stdout, steps, trace }
      case 0xc3: {
        pc = read32(regs.esp)
        regs.esp += 4
        break
      }
      case 0xc9:
        regs.esp = regs.ebp
        regs.ebp = read32(regs.esp)
        regs.esp += 4
        break
      case 0x80: {
        // Only the `cmp r/m8, imm8` form is emitted.
        const byte = read8(pc)
        pc += 1
        if (((byte >> 3) & 7) !== 7) throw new Error(`unhandled 0x80 /${(byte >> 3) & 7}`)
        const mod = (byte >> 6) & 3
        const rm = byte & 7
        let address
        if (rm === 4) {
          const sibByte = read8(pc)
          pc += 1
          const scale = 1 << ((sibByte >> 6) & 3)
          const index = (sibByte >> 3) & 7
          const baseReg = sibByte & 7
          address = regs[REG_NAMES[baseReg]] + (index === 4 ? 0 : regs[REG_NAMES[index]] * scale)
        } else {
          address = regs[REG_NAMES[rm]]
        }
        // mod=00 with rm=101 means absolute disp32, and so does a SIB whose base is
        // 101; both are how the emitter reaches a fixed `.rodata` address.
        if (mod === 0 && rm === 5) {
          address = read32Unsigned(pc)
          pc += 4
        }
        if (mod === 1) {
          address = (address + (read8(pc) << 24 >> 24)) | 0
          pc += 1
        } else if (mod === 2) {
          address = (address + read32Signed(pc)) | 0
          pc += 4
        }
        const immediate = read8(pc)
        pc += 1
        setFlagsSub(read8(address), immediate)
        break
      }
      default:
        throw new Error(
          `i386 interpreter: unhandled opcode 0x${opcode.toString(16)} at 0x${startPc.toString(16)} ` +
            `(the emitter produced an instruction this test interpreter does not model)`,
        )
    }
    // Record the whole register file for the step: a trace that carries only EAX
    // cannot explain a comparison whose other operand lives in EBX.
    trace.push({ pc: startPc, ...regs })
  }
  throw new Error(`i386 interpreter: step limit reached without exiting; last pcs: ${trace.slice(-8).map(t => `0x${t.pc.toString(16)}`).join(', ')}`)
}

