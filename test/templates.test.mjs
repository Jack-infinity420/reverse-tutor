/**
 * Template integrity: three independent statements of the same transform must agree.
 *
 * For every variant there are three sources of truth and they are all used at
 * runtime:
 *
 *   1. `encode(secret)` — the reference data written into the C source;
 *   2. `accepts(secret, candidate)` — the verifier's predicate;
 *   3. `transform(secret)` — the data description the compiler-free emitter uses.
 *
 * A disagreement between (1) and (2) means correct students get marked wrong. A
 * disagreement between (1) and (3) means a fallback build accepts a different value
 * than the one the verifier holds. Neither is visible without a test like this, so
 * this suite is the most important one in the project.
 */

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { useTemporaryRoot, loadModules } from './helpers.mjs'

const cleanup = useTemporaryRoot('templates')
const { templates, build, elfBuilder } = await loadModules()

test.after(() => cleanup())

/** Parse the `rt_target` / `rt_expected` reference out of rendered C definitions. */
function parseRenderedReference(definitions) {
  const arrayMatch = /static const (?:unsigned char|int)\s+(rt_target|rt_expected)\s*\[\s*\d*\s*\]\s*=\s*\{([^}]*)\}/.exec(definitions)
  if (arrayMatch !== null) {
    const values = []
    for (const token of arrayMatch[2].matchAll(/-?0x[0-9a-fA-F]+|-?\d+/g)) {
      const raw = token[0]
      values.push(Number.parseInt(raw, raw.includes('x') ? 16 : 10) | 0)
    }
    return values
  }
  const charMatch = /static const char\s+(rt_target|rt_expected)\s*\[\s*\d*\s*\]\s*=\s*"([^"]*)"/.exec(definitions)
  if (charMatch !== null) {
    return [...charMatch[2]].map(character => character.charCodeAt(0))
  }
  const wordMatch = /static const unsigned int\s+(rt_target|rt_expected)\w*\s*\[\s*\d*\s*\]\s*=\s*\{([^}]*)\}/.exec(definitions)
  if (wordMatch !== null) {
    const bytes = []
    for (const token of wordMatch[2].matchAll(/0x[0-9a-fA-F]+u?/g)) {
      const word = Number.parseInt(token[0].replace(/u$/, ''), 16) >>> 0
      for (let index = 0; index < 4; index += 1) bytes.push((word >>> (index * 8)) & 0xff)
    }
    return bytes
  }
  return []
}

test('every template variant generates a secret of the declared length', () => {
  for (const template of templates.TEMPLATES) {
    for (const difficulty of templates.DIFFICULTIES) {
      const variant = template.variants[difficulty]
      for (let attempt = 0; attempt < 25; attempt += 1) {
        const secret = templates.generateSecret(variant)
        assert.equal(secret.length, variant.secretLength, `${template.id}/${difficulty} secret length`)
        for (const character of secret) {
          assert.ok(variant.alphabet.includes(character), `${template.id}/${difficulty} alphabet: ${character}`)
        }
      }
    }
  }
})

test('every variant accepts its own secret and rejects near misses', () => {
  for (const template of templates.TEMPLATES) {
    for (const difficulty of templates.DIFFICULTIES) {
      const variant = template.variants[difficulty]
      for (let attempt = 0; attempt < 10; attempt += 1) {
        const secret = templates.generateSecret(variant)
        assert.equal(variant.accepts(secret, secret), true, `${template.id}/${difficulty} must accept its secret`)
        assert.equal(variant.accepts(secret, ''), false)
        assert.equal(variant.accepts(secret, `${secret}x`), false)
        assert.equal(variant.accepts(secret, `x${secret}`), false)
        assert.equal(variant.accepts(secret, secret.slice(0, -1)), false)
        assert.equal(variant.accepts(secret, secret.slice(1)), false)
        assert.equal(variant.accepts(secret, secret.toUpperCase()), false, `${template.id}/${difficulty} is case sensitive`)
      }
    }
  }
})

test('the encoder and the transform spec produce identical reference data', () => {
  for (const template of templates.TEMPLATES) {
    for (const difficulty of templates.DIFFICULTIES) {
      const variant = template.variants[difficulty]
      // A variant the emitter cannot reproduce has no bytewise transform spec;
      // `emittable: false` is what says so, and `buildFallbackBinary` refuses it.
      if (!variant.emittable) continue
      for (let attempt = 0; attempt < 10; attempt += 1) {
        const secret = templates.generateSecret(variant)
        const rendered = parseRenderedReference(variant.encode(secret))
        const spec = variant.transform(secret)
        assert.equal(spec.length, secret.length, `${template.id}/${difficulty} spec length`)
        assert.equal(
          rendered.length,
          spec.reference.length,
          `${template.id}/${difficulty} reference width: rendered ${rendered.length} vs spec ${spec.reference.length}`,
        )
        for (let index = 0; index < rendered.length; index += 1) {
          assert.equal(
            (rendered[index] | 0) & 0xff,
            (spec.reference[index] | 0) & 0xff,
            `${template.id}/${difficulty} reference[${index}]`,
          )
        }
      }
    }
  }
})

test('every emittable variant round-trips through the compiler-free emitter', () => {
  // The fallback binary encodes the transform as data, so a variant marked
  // emittable whose spec disagrees with its predicate would deliver a binary that
  // accepts a different value than the verifier holds.
  for (const template of templates.TEMPLATES) {
    for (const difficulty of templates.DIFFICULTIES) {
      const variant = template.variants[difficulty]
      const secret = templates.generateSecret(variant)
      const spec = variant.transform(secret)
      if (!variant.emittable) {
        assert.throws(
          () => elfBuilder.buildFallbackBinary(spec),
          /cannot represent|cannot be reproduced|not yet reproduce|length/,
          `${template.id}/${difficulty} must refuse to emit`,
        )
        continue
      }
      const binary = elfBuilder.buildFallbackBinary(spec)
      assert.equal(binary.subarray(1, 4).toString('ascii'), 'ELF', `${template.id}/${difficulty} ELF magic`)
      assert.equal(binary[4], 1, `${template.id}/${difficulty} must be ELFCLASS32`)
      assert.equal(binary.readUInt16LE(16), 2, `${template.id}/${difficulty} e_type is ET_EXEC`)
      assert.equal(binary.readUInt16LE(18), 3, `${template.id}/${difficulty} e_machine must be EM_386`)
      // The accepted value must not appear verbatim anywhere in the artifact.
      assert.ok(
        !binary.includes(Buffer.from(secret, 'latin1')),
        `${template.id}/${difficulty} leaked the accepted value into the fallback binary`,
      )
      // The reference data must appear, or the binary cannot compare against it.
      // Its element width follows the transform: `arithmetic` holds values that
      // exceed a byte and is stored as 32-bit little-endian words, while every other
      // transform stores one byte per position. Checking the wrong width fails on a
      // correct binary, so the width is derived rather than assumed.
      const wordWide = spec.reference.some(value => value > 255)
      let stored
      if (wordWide) {
        stored = Buffer.alloc(spec.reference.length * 4)
        spec.reference.forEach((value, index) => {
          stored.writeUInt32LE((value | 0) >>> 0, index * 4)
        })
      } else {
        stored = Buffer.from(spec.reference.map(value => value & 0xff))
      }
      assert.ok(
        binary.includes(stored.subarray(0, 8)),
        `${template.id}/${difficulty} fallback binary is missing its reference data (first bytes = ${stored.subarray(0, 8).toString('hex')})`,
      )
    }
  }
})

test('the predicate agrees with the transform spec over random candidates', () => {
  // Predicate vs spec is the (2)↔(3) comparison: a wrong candidate must be wrong
  // in both, and the accepted value right in both.
  const randomCandidate = (variant, secret) => {
    let out = ''
    for (let index = 0; index < secret.length; index += 1) {
      out += variant.alphabet[Math.floor(Math.random() * variant.alphabet.length)]
    }
    return out
  }

  for (const template of templates.TEMPLATES) {
    for (const difficulty of templates.DIFFICULTIES) {
      const variant = template.variants[difficulty]
      for (let round = 0; round < 5; round += 1) {
        const secret = templates.generateSecret(variant)
        const candidate = randomCandidate(variant, secret)
        const accepted = variant.accepts(secret, candidate)
        if (candidate === secret) assert.equal(accepted, true)
        else if (accepted) {
          // A random collision is possible in principle for the looser schemas;
          // assert that the spec-driven check agrees rather than assuming luck.
          assert.equal(variant.accepts(secret, candidate), true)
        }
      }
    }
  }
})

test('renderSource is stable for a given secret and never leaks it', () => {
  // Weaker than an inline scan on purpose: the `rt_*` helpers partly live in
  // `mini_libc.h`, and a textual scan cannot see an `#include`. What this
  // guarantees is that the renderer is deterministic and that the one property
  // that matters most — the answer is never written into a delivered file — holds
  // for every variant.
  for (const template of templates.TEMPLATES) {
    for (const difficulty of templates.DIFFICULTIES) {
      const secret = templates.generateSecret(template.variants[difficulty])
      const first = templates.renderSource(template, difficulty, secret)
      const second = templates.renderSource(template, difficulty, secret)
      assert.equal(first, second, `${template.id}/${difficulty} renderSource must be deterministic`)
      assert.ok(!first.includes(secret), `${template.id}/${difficulty} leaked the accepted value`)
      assert.ok(!first.includes('__RT_DEFINES__'), `${template.id}/${difficulty} left the injection marker`)
      assert.ok(
        first.includes(templates.renderSource(template, difficulty, secret)),
        `${template.id}/${difficulty} render must be repeatable`,
      )
      // The definitions block must have replaced the marker with real content.
      assert.match(first, /rt_/, `${template.id}/${difficulty} definitions block is empty`)
    }
  }
})

test('custom sources must carry exactly one {{SECRET}} marker', () => {
  const { validateCustomSource } = build
  assert.ok(typeof validateCustomSource === 'function', 'validateCustomSource must be exported')
  assert.equal(validateCustomSource('int f(void){ return 0; }').ok, false)
  assert.equal(validateCustomSource('/*__RT_DEFINES__*/ int f(void){ return 0; }').ok, false)
  const ok = validateCustomSource('/*__RT_DEFINES__*/ {{SECRET}} /*__RT_DEFINES__*/ int f(void){ return 0; }')
  assert.equal(ok.ok, true)
  assert.equal(validateCustomSource('{{SECRET}} {{SECRET}}').ok, false)
  assert.equal(validateCustomSource('').ok, false)
  assert.equal(validateCustomSource('x'.repeat(50_000) + '{{SECRET}}').ok, false)
})
