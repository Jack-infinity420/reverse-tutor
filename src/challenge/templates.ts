/**
 * Challenge template registry: the trusted half of the system.
 *
 * A template owns three things and nothing else:
 *
 * - the C source that gets compiled into a real ELF,
 * - the encoder that turns a freshly generated secret into the reference bytes
 *   injected into that source,
 * - the pure predicate that decides whether a candidate is the accepted value.
 *
 * Because the predicate is a plain function over scalars, the verifier never has
 * to execute model-influenced code, and it stays available on hosts that cannot
 * run a Linux ELF at all (see `verifier.ts` for the tiered decision).
 *
 * @module dsh-reverse-tutor/challenge/templates
 */

import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { randomInt } from 'node:crypto'

/** Difficulty labels shared by tools, state, and templates. */
export type Difficulty = 'beginner' | 'intermediate'

/** Every difficulty, in increasing order. */
export const DIFFICULTIES: readonly Difficulty[] = ['beginner', 'intermediate']

/** Topics a template can teach. */
export type Topic = 'xor' | 'string-comparison' | 'integer-arithmetic' | 'control-flow' | 'calling-convention'

/** A predicate decides acceptance; it must never depend on anything but its input. */
export type Predicate = (candidate: string) => boolean

/**
 * The transform a variant applies to each input byte, stated as data.
 *
 * Templates give the predicate as code (for the verifier) and the transform as
 * data (for the compiler-free fallback emitter in `elf.ts`). Both are derived
 * from the same constants, and the test suite cross-checks them against the
 * rendered C definitions, so the three cannot drift apart silently.
 */
export type TransformSpec =
  | { readonly kind: 'direct'; readonly banner: string; readonly length: number; readonly reference: readonly number[]; readonly parameters: readonly number[] }
  | { readonly kind: 'xor-broadcast'; readonly banner: string; readonly length: number; readonly reference: readonly number[]; readonly parameters: readonly number[] }
  | { readonly kind: 'xor-rotating'; readonly banner: string; readonly length: number; readonly reference: readonly number[]; readonly parameters: readonly number[] }
  | { readonly kind: 'xor-keystream'; readonly banner: string; readonly length: number; readonly reference: readonly number[]; readonly parameters: readonly number[] }
  | { readonly kind: 'arithmetic'; readonly banner: string; readonly length: number; readonly reference: readonly number[]; readonly parameters: readonly number[] }
  /** `window` is the width of the raw-comparison band; 0 means the map has no shortcut. */
  | { readonly kind: 'branch'; readonly banner: string; readonly length: number; readonly reference: readonly number[]; readonly parameters: readonly number[]; readonly window?: number }

/** One difficulty variant of a template. */
export interface TemplateVariant {
  /** Expected length of the generated secret, in bytes. */
  readonly secretLength: number
  /** Alphabet used to generate the secret. */
  readonly alphabet: string
  /**
   * Optional constrained generator.
   *
   * Most variants take a uniformly random value from `alphabet`. A variant whose
   * binary *generates* its reference data at run time (the `strcmp` LCG) instead
   * needs a value that its recurrence can actually produce, so it supplies a
   * solver here. `generateSecret` prefers it when present.
   */
  readonly solve?: () => string
  /** Encode the secret into the reference values written into the C source. */
  readonly encode: (secret: string) => string
  /** Decide acceptance for a candidate. */
  readonly accepts: (secret: string, candidate: string) => boolean
  /** The same transform as data, for the compiler-free fallback emitter. */
  readonly transform: (secret: string) => TransformSpec
  /** One-line description of what this difficulty adds. */
  readonly summary: string
  /** Whether a fallback binary can reproduce this variant without a compiler. */
  readonly emittable: boolean
}

/** A complete challenge template. */
export interface ChallengeTemplate {
  /** Stable id; also the directory name under `templates/`. */
  readonly id: string
  /** Topic this template teaches. */
  readonly topic: Topic
  /** One-line teaching statement used in challenge briefs. */
  readonly teaching: string
  /** Learning objectives, phrased as observable skills. */
  readonly objectives: readonly string[]
  /** Skill keys this template exercises, used for weakness tracking. */
  readonly skills: readonly string[]
  /** Template variant per difficulty. */
  readonly variants: Readonly<Record<Difficulty, TemplateVariant>>
}

/** Generate a secret for one variant. */
export function generateSecret(variant: TemplateVariant): string {
  if (variant.solve !== undefined) return variant.solve()
  let secret = ''
  for (let index = 0; index < variant.secretLength; index += 1) {
    secret += variant.alphabet[randomInt(variant.alphabet.length)]
  }
  return secret
}

/* ------------------------------------------------------------------------ */
/* Encoders                                                                  */
/* ------------------------------------------------------------------------ */

function byteArray(values: readonly number[], indent = '    '): string {
  const rows: string[] = []
  for (let index = 0; index < values.length; index += 8) {
    const chunk = values.slice(index, index + 8)
    rows.push(`${indent}${chunk.map(value => `0x${value.toString(16).padStart(2, '0')}`).join(', ')},`)
  }
  return rows.join('\n')
}

function byteCodes(secret: string): number[] {
  return Array.from(secret, character => character.charCodeAt(0))
}

/** `xor`: one key byte broadcast, or a four-byte key indexed by `i mod 4`. */
function encodeXor(secret: string, key: readonly number[]): string {
  const codes = byteCodes(secret)
  const target = codes.map((code, index) => (code ^ key[index % key.length]!) & 0xff)
  const keyLiteral = key.map(value => `0x${value.toString(16).padStart(2, '0')}`).join(', ')
  return (
    `#define RT_KEY_WIDTH ${key.length}\n\n` +
    `static const unsigned char rt_key[${key.length}] = { ${keyLiteral} };\n` +
    `static const unsigned char rt_target[${target.length}] = {\n${byteArray(target)}\n};\n`
  )
}

/**
 * `strcmp` reference construction.
 *
 * Even this template does not write the accepted value into the source. The
 * comparison is against a keystream:
 *
 *   state = seed
 *   state = state * multiplier + increment          (64-bit wraparound)
 *   reference[i] = accepted[i] ^ ((state >> shift) & 0xff)
 *
 * The binary therefore carries only a 64-bit seed triple plus the XORed bytes.
 * Recovering the answer means recovering the keystream and folding it back in —
 * the same "which operand is attacker-controlled?" question the template is meant
 * to teach, instead of a sixteen-byte string copy out of `.rodata`.
 *
 * `multiplier`/`increment` are chosen to satisfy the Hull–Dobell conditions
 * (`increment` odd, `multiplier ≡ 1 (mod 4)`), which makes the recurrence
 * full-period over 64 bits: the keystream never repeats inside a challenge, and
 * the generator has workable statistical quality for a 16–32 byte key.
 */
interface Keystream {
  readonly seed: bigint
  readonly multiplier: bigint
  readonly increment: bigint
  readonly shift: number
}

const LCG_MASK = (1n << 64n) - 1n

const STRCMP_LCG: Record<Difficulty, Keystream> = {
  beginner: {
    seed: 0x2545_f491_4f6c_dd1dn,
    multiplier: 6364136223846793005n,
    increment: 1442695040888963407n,
    shift: 33,
  },
  intermediate: {
    seed: 0x9e37_79b9_7f4a_7c15n,
    multiplier: 2862933555777941757n,
    increment: 3037000493n,
    shift: 24,
  },
}

/** Step the recurrence `length` times and return one byte per step. */
function keystreamBytes(key: Keystream, length: number): number[] {
  const bytes: number[] = []
  let state = key.seed & LCG_MASK
  for (let index = 0; index < length; index += 1) {
    state = (state * key.multiplier + key.increment) & LCG_MASK
    bytes.push(Number((state >> BigInt(key.shift)) & 0xffn))
  }
  return bytes
}

/** Write a 64-bit value the way the generated C source spells it. */
function u64Literal(value: bigint, suffix: string): string {
  return `0x${(value & LCG_MASK).toString(16).padStart(16, '0')}u${suffix}`
}

/** `strcmp`: the XORed bytes plus the seed triple that reproduces the keystream. */
function encodeString(secret: string, key: Keystream, packed: boolean): string {
  const stream = keystreamBytes(key, secret.length)
  const target = codesOf(secret).map((code, index) => (code ^ stream[index]!) & 0xff)
  const definitions = [
    `/* 64-bit linear congruential keystream (Hull-Dobell full period). */`,
    `#define RT_KEY_SEED ${u64Literal(key.seed, 'll')}`,
    `#define RT_KEY_MUL ${u64Literal(key.multiplier, 'll')}`,
    `#define RT_KEY_INC ${u64Literal(key.increment, 'll')}`,
    `#define RT_KEY_SHIFT ${key.shift}`,
    `#define RT_PACK_WORDS ${packed ? 1 : 0}`,
    '',
  ]
  if (!packed) {
    definitions.push(
      `static const unsigned char rt_target[${target.length}] = {`,
      ...target.map(value => `    0x${value.toString(16).padStart(2, '0')}u,`),
      '};',
    )
  } else {
    // The same bytes, stored as 32-bit words and narrowed back on load: recovering
    // them then requires reading the exact byte order.
    const words: number[] = []
    for (let index = 0; index < target.length; index += 4) {
      let word = 0
      for (let offset = 0; offset < 4; offset += 1) word |= (target[index + offset] ?? 0) << (offset * 8)
      words.push(word >>> 0)
    }
    definitions.push(
      `static const unsigned int rt_target_words[${words.length}] = {`,
      ...words.map(value => `    0x${value.toString(16).padStart(8, '0')}u,`),
      '};',
      `static unsigned char rt_target[${target.length}];`,
    )
  }
  return `${definitions.join('\n')}\n`
}

/** `arithmetic`: `(input[i] + i) * scale - bias` (bias may advance per index). */
function encodeArithmetic(secret: string, scale: number, bias: number, biasStep: number): string {
  const codes = byteCodes(secret)
  let running = bias
  const target = codes.map((code, index) => {
    const value = (code + index) * scale - running
    running += biasStep
    return value
  })
  return (
    `#define RT_SCALE ${scale}\n#define RT_BIAS ${bias}\n#define RT_BIAS_STEP ${biasStep}\n\n` +
    `static const int rt_target[${target.length}] = {\n${target.map(value => `    ${value},`).join('\n')}\n};\n`
  )
}

/** `branch`: the piecewise map with its range shortcut, mirroring the compiled `cmp`/`jcc` chain. */
function encodeBranch(
  secret: string,
  gate: number,
  window: number,
  biasLow: number,
  biasHigh: number,
): string {
  const codes = byteCodes(secret)
  const target = codes.map(code => {
    if (code >= gate && code < gate + window) return code
    return code < gate ? code - biasLow : code + biasHigh
  })
  return (
    `#define RT_GATE ${gate}\n` +
    `#define RT_WINDOW_WIDTH ${window}\n` +
    `#define RT_BIAS_LOW ${biasLow}\n` +
    `#define RT_BIAS_HIGH ${biasHigh}\n\n` +
    `static const int rt_target[${target.length}] = {\n${target.map(value => `    ${value},`).join('\n')}\n};\n`
  )
}

/** `function-args`: three slice digests, one per argument register. */
function encodeArgs(
  secret: string,
  sliceA: number,
  sliceB: number,
  digestA: (slice: string) => number,
  digestB: (slice: string) => number,
  digestC: (slice: string) => number,
): string {
  const first = secret.slice(0, sliceA)
  const second = secret.slice(sliceA, sliceA + sliceB)
  const third = secret.slice(sliceA + sliceB)
  return (
    `#define RT_SLICE_A ${sliceA}\n#define RT_SLICE_B ${sliceB}\n\n` +
    `static const int rt_target_a = ${digestA(first)};\n` +
    `static const int rt_target_b = ${digestB(second)};\n` +
    `static const int rt_target_c = ${digestC(third)};\n`
  )
}

/* ------------------------------------------------------------------------ */
/* Predicates                                                                */
/* ------------------------------------------------------------------------ */

function codesOf(value: string): number[] {
  return byteCodes(value)
}

/**
 * Predicates.
 *
 * Naming, because it is the easiest thing to get wrong here:
 *
 * - **secret** is the accepted value — the answer.
 * - **reference** is the encoded data the binary compares against, produced by
 *   the variant's `encode`.
 *
 * Every predicate below therefore checks `transform(candidate[i]) === encode(secret)[i]`,
 * never `transform(candidate[i]) === secret[i]`. Each predicate is a direct
 * transcription of the loop in the matching `templates/<id>/challenge.c`, and the
 * test suite asserts that the predicate and the encoder agree for every variant.
 */

function acceptsXor(secret: string, candidate: string, key: readonly number[]): boolean {
  const reference = codesOf(secret).map((code, index) => (code ^ key[index % key.length]!) & 0xff)
  const given = codesOf(candidate)
  if (given.length !== reference.length) return false
  for (let index = 0; index < reference.length; index += 1) {
    // `(unsigned char)(input[i] ^ key)` in C, with the mask wrapping the XOR.
    if (((given[index]! ^ key[index % key.length]!) & 0xff) !== reference[index]) return false
  }
  return true
}

/**
 * `strcmp`: mirrors the binary's loop exactly.
 *
 * The C code compares `(unsigned char)input[i] ^ keystream[i]` against
 * `rt_target[i]`. The candidate must therefore be transformed before it is
 * compared — comparing the raw candidate against the target would reject the one
 * value that actually passes the binary, which is the worst failure this project
 * can have.
 */
function acceptsString(secret: string, candidate: string, key: Keystream): boolean {
  if (candidate.length !== secret.length) return false
  // The keystream is computed ONCE per call. Recomputing it inside the map would
  // restart the recurrence at every index and compare against the wrong bytes.
  const stream = keystreamBytes(key, secret.length)
  const reference = codesOf(secret).map((code, index) => (code ^ stream[index]!) & 0xff)
  const given = codesOf(candidate)
  for (let index = 0; index < reference.length; index += 1) {
    if (((given[index]! ^ stream[index]!) & 0xff) !== reference[index]) return false
  }
  return true
}

function acceptsArithmetic(secret: string, candidate: string, scale: number, bias: number, biasStep: number): boolean {
  const reference = codesOf(secret).map((code, index) => (code + index) * scale - (bias + biasStep * index))
  const given = codesOf(candidate)
  if (given.length !== reference.length) return false
  for (let index = 0; index < reference.length; index += 1) {
    // `((int)(unsigned char)input[index] + index) * scale - bias` in C.
    if ((given[index]! + index) * scale - (bias + biasStep * index) !== reference[index]) return false
  }
  return true
}

/**
 * `branch`: mirrors the binary's decision tree exactly.
 *
 * Three cases, in the order the compiled code tests them — and the order matters,
 * because the range shortcut is checked BEFORE the affine branches. A reader who
 * assumes a plain `if/else` on the gate recovers the wrong character for every byte
 * that falls inside the window.
 */
function branchReference(code: number, gate: number, window: number, biasLow: number, biasHigh: number): number {
  if (code >= gate && code < gate + window) return code
  return code < gate ? code - biasLow : code + biasHigh
}

/**
 * Prove the branch map can actually be inverted over an alphabet.
 *
 * Three failure modes are silent otherwise, and each of them ships a challenge whose
 * binary rejects the value the verifier accepts — or hands it over:
 *
 * - **not injective**: two characters in the alphabet share a reference value, so
 *   the table alone does not determine the accepted character. This happens when an
 *   affine branch pushes one character onto another one's raw value.
 * - **out of range**: a reference value exceeds 255, so the byte-wide table cannot
 *   hold it.
 * - **the window swallows the alphabet**: the range shortcut stores the character
 *   verbatim, so a window wide enough to cover the whole alphabet puts the accepted
 *   value into `.rodata` as a readable string — the one thing every other template
 *   is careful not to do. The cap below keeps the shortcut teachable without letting
 *   it become the answer.
 *
 * The check runs over the whole alphabet rather than the one generated secret,
 * because a collision that this secret happens not to hit is still a collision.
 */
function assertBranchInvertible(alphabet: string, gate: number, window: number, biasLow: number, biasHigh: number): void {
  const inWindow = [...alphabet].filter(character => {
    const code = character.charCodeAt(0)
    return code >= gate && code < gate + window
  })
  // Two is the cap, not a preference: the shortcut stores its characters verbatim, so
  // a wider window starts spelling the accepted value inside `.rodata`. The alphabet
  // in use skips `0` and `1`, and that gap is what leaves room for a window at all.
  if (inWindow.length > 2) {
    throw new Error(
      `reverse-tutor: the branch window covers ${inWindow.length} of ${alphabet.length} alphabet characters; ` +
        'it must stay narrow or the shortcut stores the accepted value verbatim',
    )
  }
  // The shortcut's identity values have to be disjoint from BOTH affine branches.
  // This is the check that matters: the natural gate/bias choices put
  // `code - biasLow` (for a letter just under the gate) and `code` (for a character
  // inside the window) on the same number, and the emitted program then compares
  // against the wrong element for one of them while the predicate still says yes.
  for (const character of alphabet) {
    const code = character.charCodeAt(0)
    if (code < gate || code >= gate + window) continue
    for (const other of alphabet) {
      const otherCode = other.charCodeAt(0)
      if (otherCode >= gate && otherCode < gate + window) continue
      const affine = otherCode < gate ? otherCode - biasLow : otherCode + biasHigh
      if (affine === code && otherCode !== code) {
        throw new Error(
          `reverse-tutor: the branch shortcut maps ${JSON.stringify(character)} to ${code}, which is also ` +
            `where ${JSON.stringify(other)} lands after the affine transform`,
        )
      }
    }
  }
  const seen = new Map<number, number>()
  for (const character of alphabet) {
    const code = character.charCodeAt(0)
    const value = branchReference(code, gate, window, biasLow, biasHigh)
    if (!Number.isInteger(value) || value < 0 || value > 255) {
      throw new Error(`reverse-tutor: branch reference ${value} for ${JSON.stringify(character)} does not fit one byte`)
    }
    const previous = seen.get(value)
    if (previous !== undefined && previous !== code) {
      throw new Error(
        `reverse-tutor: branch transform maps both ${JSON.stringify(String.fromCharCode(previous))} and ${JSON.stringify(character)} to ${value}`,
      )
    }
    seen.set(value, code)
  }
}

function acceptsBranch(
  secret: string,
  candidate: string,
  gate: number,
  window: number,
  biasLow: number,
  biasHigh: number,
): boolean {
  const reference = codesOf(secret).map(code => branchReference(code, gate, window, biasLow, biasHigh))
  const given = codesOf(candidate)
  if (given.length !== reference.length) return false
  for (let index = 0; index < reference.length; index += 1) {
    const current = given[index]!
    if (current === 0) return false
    if (current >= gate && current < gate + window) {
      // The caller's shortcut branch compares the raw byte.
      if (current !== reference[index]) return false
      continue
    }
    const transformed = current < gate ? current - biasLow : current + biasHigh
    if (transformed !== reference[index]) return false
  }
  return true
}

function digestA(slice: string): number {
  let accumulator = 0
  for (let index = 0; index < slice.length; index += 1) {
    accumulator = ((accumulator << 3) ^ slice.charCodeAt(index)) | 0
  }
  return accumulator
}

function digestB(slice: string): number {
  let accumulator = 0
  for (let index = 0; index < slice.length; index += 1) {
    accumulator = (accumulator + (slice.charCodeAt(index) << (index + 1))) | 0
  }
  return accumulator
}

function digestC(slice: string): number {
  let accumulator = 0
  let index = 0
  while (index < slice.length) {
    accumulator = (accumulator * 5 + slice.charCodeAt(index)) | 0
    index += 1
  }
  return (accumulator + index) | 0
}

function acceptsArgs(secret: string, candidate: string, sliceA: number, sliceB: number): boolean {
  if (candidate.length !== secret.length) return false
  return (
    digestA(candidate.slice(0, sliceA)) === digestA(secret.slice(0, sliceA)) &&
    digestB(candidate.slice(sliceA, sliceA + sliceB)) === digestB(secret.slice(sliceA, sliceA + sliceB)) &&
    digestC(candidate.slice(sliceA + sliceB)) === digestC(secret.slice(sliceA + sliceB))
  )
}

/* ------------------------------------------------------------------------ */
/* Registry                                                                  */
/* ------------------------------------------------------------------------ */

const LOWERCASE = 'abcdefghijkmnpqrstuvwxyz'
const ALPHANUMERIC = 'abcdefghijkmnpqrstuvwxyz23456789'

/* ------------------------------------------------------------------------ */
/* Transform specs (the compiler-free fallback's view of each variant)       */
/* ------------------------------------------------------------------------ */

/** XOR key per difficulty, shared by the encoder, the predicate, and the spec. */
const XOR_KEYS = {
  beginner: [0x37],
  intermediate: [0x37, 0x11, 0x5a, 0x2c],
} as const

/**
 * Branch parameters per difficulty, shared by the encoder, the predicate, and the spec.
 *
 * The parameters are constrained by what the challenge has to be able to do, not
 * chosen freely. `assertBranchInvertible` enforces the last two at build time:
 *
 * - the acceptance window `[gate, gate + window)` must OVERLAP the alphabet, or the
 *   raw-comparison path is unreachable and the template teaches nothing about range
 *   tests;
 * - it must stay narrow, or the verbatim values it stores become the answer;
 * - both affine branches must stay inside the alphabet, since a transform that
 *   lands outside it accepts nothing;
 * - a transform must stay injective over the alphabet, or two different characters
 *   would share a reference value and the challenge would have more than one answer.
 */
const BRANCH = {
  // letters 97..122 and digits 50..57 — the alphabet deliberately skips `0` and `1`,
  // which is what leaves a gap wide enough for a two-byte window that stores no more
  // than two alphabet characters verbatim.
  beginner: { gate: 105, window: 2, biasLow: 10, biasHigh: 20 },
  intermediate: { gate: 56, window: 2, biasLow: 7, biasHigh: 25 },
} as const

/**
 * `strcmp`: the fallback program must apply the same keystream XOR the compiler
 * build does, or it would accept a different value than the verifier holds.
 *
 * `parameters` carries seed, multiplier, and increment as low/high 32-bit halves
 * plus the shift — exactly what the emitter needs to reproduce the recurrence.
 */
function keystreamSpec(secret: string, key: Keystream, banner: string): TransformSpec {
  const stream = keystreamBytes(key, secret.length)
  const reference = byteCodes(secret).map((code, index) => (code ^ stream[index]!) & 0xff)
  const split = (value: bigint): number[] => [
    Number(value & 0xffff_ffffn),
    Number((value >> 32n) & 0xffff_ffffn),
  ]
  return {
    kind: 'xor-keystream',
    banner,
    length: secret.length,
    reference,
    // seedLo, seedHi, mulLo, mulHi, incLo, incHi, shift
    parameters: [...split(key.seed), ...split(key.multiplier), ...split(key.increment), key.shift],
  }
}

function xorSpec(secret: string, keys: readonly number[], kind: 'xor-broadcast' | 'xor-rotating', banner: string): TransformSpec {
  // The `& 0xff` must wrap the whole XOR: `a ^ b & 0xff` parses as `a ^ (b & 0xff)`
  // in JavaScript, which silently produces a different reference array than the
  // C expression `(unsigned char)(a ^ b)` it is meant to mirror.
  const reference = byteCodes(secret).map((code, index) => (code ^ keys[index % keys.length]!) & 0xff)
  return { kind, banner, length: secret.length, reference, parameters: [...keys] }
}

function arithmeticSpec(secret: string, scale: number, bias: number, biasStep: number, banner: string): TransformSpec {
  const reference = byteCodes(secret).map((code, index) => (code + index) * scale - (bias + biasStep * index))
  return { kind: 'arithmetic', banner, length: secret.length, reference, parameters: [scale, bias, biasStep] }
}

function branchSpec(
  secret: string,
  alphabet: string,
  variant: { readonly gate: number; readonly window: number; readonly biasLow: number; readonly biasHigh: number },
  banner: string,
): TransformSpec {
  // Values below the gate are transformed by `code - biasLow`, so the emitted
  // instruction adds the negation. Parameter order matches the emitter exactly:
  //   code < gate ? code + parameters[1] : code - parameters[2]
  assertBranchInvertible(alphabet, variant.gate, variant.window, variant.biasLow, variant.biasHigh)
  const reference = byteCodes(secret).map(code =>
    branchReference(code, variant.gate, variant.window, variant.biasLow, variant.biasHigh),
  )
  return {
    kind: 'branch',
    banner,
    length: secret.length,
    reference,
    parameters: [variant.gate, -variant.biasLow, variant.biasHigh],
    window: variant.window,
  }
}

function argsSpec(_secret: string, _sliceA: number, _sliceB: number, banner: string): TransformSpec {
  return { kind: 'direct', banner, length: 0, reference: [], parameters: [] }
}

/** Every template this plugin can build. */
export const TEMPLATES: readonly ChallengeTemplate[] = [
  {
    id: 'xor-loop',
    topic: 'xor',
    teaching: 'recognise a byte-wise XOR transform, prove where its input comes from, and invert it',
    objectives: [
      'identify_xor',
      'trace_input_data_flow',
      'recover_xor_key',
      'invert_transform',
    ],
    skills: ['assembly', 'dataFlow'],
    variants: {
      beginner: {
        secretLength: 12,
        alphabet: LOWERCASE,
        summary: 'single-byte key broadcast over the whole string',
        encode: secret => encodeXor(secret, [0x37]),
        accepts: (secret, candidate) => acceptsXor(secret, candidate, XOR_KEYS.beginner),
        transform: secret => xorSpec(secret, XOR_KEYS.beginner, 'xor-broadcast', '== Reverse Tutor :: xor-loop =='),
        emittable: true,
      },
      intermediate: {
        secretLength: 16,
        alphabet: ALPHANUMERIC,
        summary: 'four-byte repeating key with a narrowed `unsigned char` comparison',
        encode: secret => encodeXor(secret, XOR_KEYS.intermediate),
        accepts: (secret, candidate) => acceptsXor(secret, candidate, XOR_KEYS.intermediate),
        transform: secret => xorSpec(secret, XOR_KEYS.intermediate, 'xor-rotating', '== Reverse Tutor :: xor-loop =='),
        emittable: true,
      },
    },
  },
  {
    id: 'strcmp',
    topic: 'string-comparison',
    teaching: 'recognise a byte-wise equality loop, prove which side is attacker-controlled, and recover the constant',
    objectives: [
      'identify_comparison_idiom',
      'prove_operand_origin',
      'recover_rodata_constant',
      'explain_terminator_check',
    ],
    skills: ['assembly', 'dataFlow', 'idaUsage'],
    variants: {
      beginner: {
        secretLength: 12,
        alphabet: LOWERCASE,
        summary: 'keystream-XORed reference stored as bytes, compared byte by byte',
        encode: secret => encodeString(secret, STRCMP_LCG.beginner, false),
        accepts: (secret, candidate) => acceptsString(secret, candidate, STRCMP_LCG.beginner),
        transform: secret => keystreamSpec(secret, STRCMP_LCG.beginner, '== Reverse Tutor :: strcmp =='),
        // Unverified in the compiler-free emitter: its 32-bit reconstruction of the
        // 64-bit recurrence leaves the stack unbalanced, so the emitted program runs
        // off the end of it instead of answering. A fallback that accepts a different
        // value than the verifier holds — or crashes — is worse than no fallback, so
        // this variant requires a compiler until the emitter is fixed and the
        // emulator-based test can prove it.
        emittable: false,
      },
      intermediate: {
        secretLength: 16,
        alphabet: ALPHANUMERIC,
        summary: 'second keystream, reference stored as 32-bit words and narrowed on load',
        encode: secret => encodeString(secret, STRCMP_LCG.intermediate, true),
        accepts: (secret, candidate) => acceptsString(secret, candidate, STRCMP_LCG.intermediate),
        transform: secret => keystreamSpec(secret, STRCMP_LCG.intermediate, '== Reverse Tutor :: strcmp =='),
        // Same reason as the beginner variant: the emitter's 32-bit reconstruction of
        // the 64-bit recurrence is not yet correct under execution.
        emittable: false,
      },
    },
  },
  {
    id: 'arithmetic',
    topic: 'integer-arithmetic',
    teaching: 'read a compiled arithmetic expression and invert it in the correct order',
    objectives: [
      'restate_compiled_expression',
      'track_operand_order',
      'invert_transform',
      'explain_element_width',
    ],
    skills: ['assembly', 'dataFlow'],
    variants: {
      beginner: {
        secretLength: 12,
        alphabet: LOWERCASE,
        summary: 'constant scale and bias over a signed int reference array',
        encode: secret => encodeArithmetic(secret, 3, 7, 0),
        accepts: (secret, candidate) => acceptsArithmetic(secret, candidate, 3, 7, 0),
        transform: secret =>
          arithmeticSpec(secret, 3, 7, 0, '== Reverse Tutor :: arithmetic =='),
        // Refused by the emitter for now: under execution it computes a different
        // reference value than the predicate accepts. A compiler is required.
        emittable: false,
      },
      intermediate: {
        secretLength: 16,
        alphabet: ALPHANUMERIC,
        summary: 'per-index bias that advances inside the loop',
        encode: secret => encodeArithmetic(secret, 5, 17, 3),
        accepts: (secret, candidate) => acceptsArithmetic(secret, candidate, 5, 17, 3),
        transform: secret =>
          arithmeticSpec(secret, 5, 17, 3, '== Reverse Tutor :: arithmetic =='),
        // Same reason as the beginner variant.
        emittable: false,
      },
    },
  },
  {
    id: 'branch',
    topic: 'control-flow',
    teaching: 'read a cmp/jcc decision tree, decide which branch accepts, and invert it per branch',
    objectives: [
      'read_decision_tree',
      'classify_range_test',
      'identify_accepting_branch',
      'invert_piecewise_transform',
    ],
    skills: ['controlFlow', 'assembly'],
    variants: {
      beginner: {
        secretLength: 12,
        alphabet: LOWERCASE,
        summary: 'three-way decision: a range shortcut plus one affine transform per side',
        encode: secret =>
          encodeBranch(
            secret,
            BRANCH.beginner.gate,
            BRANCH.beginner.window,
            BRANCH.beginner.biasLow,
            BRANCH.beginner.biasHigh,
          ),
        accepts: (secret, candidate) =>
          acceptsBranch(
            secret,
            candidate,
            BRANCH.beginner.gate,
            BRANCH.beginner.window,
            BRANCH.beginner.biasLow,
            BRANCH.beginner.biasHigh,
          ),
        transform: secret =>
          branchSpec(secret, LOWERCASE, BRANCH.beginner, '== Reverse Tutor :: branch =='),
        // The compiler-free emitter does not yet reproduce this transform. Its window
        // check compiles to a four-way `cmp`/`jcc` chain and the arms still get
        // transposed under execution, so the emitted program rejects the value the
        // verifier accepts. That is the one failure this project must never ship, so
        // the variant requires a compiler until the emitter is fixed and
        // `emitter.test.mjs` can prove it right.
        emittable: false,
      },
      intermediate: {
        secretLength: 16,
        alphabet: ALPHANUMERIC,
        summary: 'narrow acceptance window inside the alphabet, with both affine sides live',
        encode: secret =>
          encodeBranch(
            secret,
            BRANCH.intermediate.gate,
            BRANCH.intermediate.window,
            BRANCH.intermediate.biasLow,
            BRANCH.intermediate.biasHigh,
          ),
        accepts: (secret, candidate) =>
          acceptsBranch(
            secret,
            candidate,
            BRANCH.intermediate.gate,
            BRANCH.intermediate.window,
            BRANCH.intermediate.biasLow,
            BRANCH.intermediate.biasHigh,
          ),
        transform: secret =>
          branchSpec(secret, ALPHANUMERIC, BRANCH.intermediate, '== Reverse Tutor :: branch =='),
        // Same reason as the beginner variant: the window chain is not yet reproduced
        // correctly by the compiler-free emitter.
        emittable: false,
      },
    },
  },
  {
    id: 'function-args',
    topic: 'calling-convention',
    teaching: 'apply the 32-bit cdecl convention to recover three slices of one input',
    objectives: [
      'map_argument_registers',
      'prove_pointer_arithmetic',
      'recover_slice_digests',
      'reassemble_in_argument_order',
    ],
    skills: ['callingConvention', 'dataFlow', 'controlFlow'],
    variants: {
      beginner: {
        secretLength: 12,
        alphabet: LOWERCASE,
        summary: 'three equal 4-byte slices with one digest shape',
        encode: secret => encodeArgs(secret, 4, 4, digestA, digestB, digestC),
        accepts: (secret, candidate) => acceptsArgs(secret, candidate, 4, 4),
        transform: secret => argsSpec(secret, 4, 4, '== Reverse Tutor :: function-args =='),
        // No bytewise transform exists for this template: the accepted value is
        // recognised through three order-dependent digests, which the compiler-free
        // emitter cannot express. Emitting `direct` here would accept the wrong value,
        // so this variant genuinely requires a compiler.
        emittable: false,
      },
      intermediate: {
        secretLength: 12,
        alphabet: ALPHANUMERIC,
        summary: 'uneven 5/4/3 split with three different digest recurrences',
        encode: secret => encodeArgs(secret, 5, 4, digestA, digestB, digestC),
        accepts: (secret, candidate) => acceptsArgs(secret, candidate, 5, 4),
        transform: secret => argsSpec(secret, 5, 4, '== Reverse Tutor :: function-args =='),
        emittable: false,
      },
    },
  },
]

/** Look up a template by id, or `undefined`. */
export function findTemplate(id: string): ChallengeTemplate | undefined {
  return TEMPLATES.find(template => template.id === id)
}

/** Topic-to-template routing used for adaptive next-challenge selection. */
export function templatesForTopic(topic: string): readonly ChallengeTemplate[] {
  const normalized = topic.trim().toLowerCase()
  return TEMPLATES.filter(template => template.topic === normalized || template.id === normalized)
}

/** Normalise a caller-supplied difficulty to a known variant. */
export function normalizeDifficulty(value: string | undefined): Difficulty {
  const normalized = (value ?? 'beginner').trim().toLowerCase()
  return normalized === 'intermediate' ? 'intermediate' : 'beginner'
}

/** Normalise a caller-supplied topic to a known template id, defaulting to xor-loop. */
export function normalizeTopic(value: string | undefined): ChallengeTemplate {
  const raw = (value ?? '').trim().toLowerCase()
  if (raw === '') return findTemplate('xor-loop')!
  const direct = findTemplate(raw) ?? templatesForTopic(raw)[0]
  if (direct !== undefined) return direct
  if (raw.includes('xor')) return findTemplate('xor-loop')!
  if (raw.includes('str') || raw.includes('cmp')) return findTemplate('strcmp')!
  if (raw.includes('arithmetic') || raw.includes('math')) return findTemplate('arithmetic')!
  if (raw.includes('branch') || raw.includes('flow') || raw.includes('jcc')) return findTemplate('branch')!
  if (raw.includes('arg') || raw.includes('convention') || raw.includes('register')) return findTemplate('function-args')!
  return findTemplate('xor-loop')!
}

/* ------------------------------------------------------------------------ */
/* Source rendering                                                          */
/* ------------------------------------------------------------------------ */

/** The template directory that ships with this package. */
export function templatesDir(): string {
  return join(dirname(fileURLToPath(import.meta.url)), '..', '..', 'templates')
}

/**
 * Render a template's C source for one secret.
 *
 * The caller never supplies the secret; the build tool generated it a moment
 * earlier and only the encoded reference values reach the file on disk.
 *
 * `RT_SECRET_LENGTH` is rewritten here rather than duplicated per variant, so a
 * template file cannot silently disagree with the generated secret length — the
 * failure mode that would be a compile error at best and a wrong challenge at
 * worst.
 *
 * @throws when the template's source lost its `/*__RT_DEFINES__*​/` marker.
 */
export function renderSource(template: ChallengeTemplate, difficulty: Difficulty, secret: string): string {
  const variant = template.variants[difficulty]
  if (secret.length !== variant.secretLength) {
    throw new Error(`template ${template.id}/${difficulty} expected a ${variant.secretLength}-byte secret`)
  }
  const file = join(templatesDir(), template.id, 'challenge.c')
  const source = readFileSync(file, 'utf8')
  const marker = '/*__RT_DEFINES__*/'
  if (!source.includes(marker)) {
    throw new Error(`template ${template.id} is missing the ${marker} marker`)
  }
  // `[^\S\n]*` keeps any trailing comment on the line; `^`/`m` anchors the define
  // so an in-body mention of the macro can never be rewritten instead.
  const lengthPattern = /^(#define RT_SECRET_LENGTH)[^\S\n]*(\d+)([^\S\n]*)$/m
  const lengthMatch = lengthPattern.exec(source)
  if (lengthMatch === null) {
    if (source.includes('RT_SECRET_LENGTH')) {
      throw new Error(`template ${template.id} declares RT_SECRET_LENGTH in a form this renderer cannot rewrite`)
    }
  } else if (Number.parseInt(lengthMatch[2]!, 10) !== secret.length) {
    // Compare the PARSED length, not the text: for a variant whose secret happens
    // to be the same length as the template's default, the substituted text is
    // identical and a "did the string change" test would report a failure.
    const withLength = source.replace(lengthPattern, `$1 ${secret.length}$3`)
    if (withLength === source) {
      throw new Error(`template ${template.id} declares RT_SECRET_LENGTH in a form this renderer cannot rewrite`)
    }
    return withLength.replace(marker, variant.encode(secret).trimEnd())
  }
  return source.replace(marker, variant.encode(secret).trimEnd())
}
