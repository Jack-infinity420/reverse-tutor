/**
 * The compiler-free emitter, executed rather than inspected.
 *
 * `challenge/elf.ts` writes real i386 machine code, and its failure mode is the
 * worst in the project: a fallback challenge that accepts a different value than
 * the verifier holds. There is no emulator on this host, so `test/emulator.mjs`
 * interprets the emitted program instead — which means these assertions rest on
 * execution, not on reading the disassembly.
 */

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { useTemporaryRoot, loadModules } from './helpers.mjs'
import { runI386 } from './emulator.mjs'

const cleanup = useTemporaryRoot('emit')
const { templates, elfBuilder, inspectElf } = await loadModules()

test.after(() => cleanup())

/**
 * Run an emitted image the way the kernel would.
 *
 * The interpreter is handed the FILE bytes plus the virtual address those bytes
 * map to, and maps each `PT_LOAD` segment itself — the same translation a loader
 * performs. Feeding it a buffer that assumed the code sits at offset 0 is how the
 * first version of this test read past the end of `.text` and executed zeroed
 * padding.
 *
 * The mapped region spans from below the image to above its stack, because the
 * interpreter keeps the stack inside the same address space.
 */
function run(binary, input) {
  const path = join(process.env['DSH_REVERSE_TUTOR_ROOT'], `emit-${Math.random().toString(16).slice(2)}.elf`)
  writeFileSync(path, binary)
  const info = inspectElf.parseElf(path)

  const loads = info.segments.filter(segment => segment.type === 1)
  assert.ok(loads.length > 0, 'an emitted image must declare a PT_LOAD segment')
  const lowest = Math.min(...loads.map(segment => segment.vaddr))
  const highest = Math.max(...loads.map(segment => segment.vaddr + segment.memSize))
  // The interpreter's stack lives at 0xffff0000, so the region has to reach it.
  const base = 0x0800_0000
  const memory = new Uint8Array(0xffff_0000 + 0x1_0000 - base)
  for (const segment of loads) {
    for (let i = 0; i < segment.fileSize; i += 1) {
      memory[segment.vaddr - base + i] = binary[segment.offset + i]
    }
  }
  assert.ok(lowest >= base && highest <= 0xffff_0000, 'image must fit the mapped region')
  return runI386(memory, info.entry, base, input)
}

/**
 * Every template that does not opt out must round-trip, in both directions.
 *
 * A template that declares itself emittable is a promise that the deterministic
 * builder reproduces its transform. The tests run the emitted program, so the
 * promise is checked by execution.
 */
test('every emittable variant accepts its own value and rejects near misses', () => {
  const unemittable = []
  let checked = 0
  for (const template of templates.TEMPLATES) {
    const variant = template.variants.beginner
    if (!variant.emittable) {
      unemittable.push(template.id)
      assert.throws(
        () => elfBuilder.buildFallbackBinary(variant.transform('x')),
        /compiler is required/,
        `${template.id} declares itself unemittable, so the emitter must refuse it`,
      )
      continue
    }
    checked += 1

    for (let round = 0; round < 3; round += 1) {
      const secret = templates.generateSecret(variant)
      const binary = elfBuilder.buildFallbackBinary(variant.transform(secret))

      // The accepted value must be accepted by the PROGRAM, not merely by the spec.
      const right = run(binary, `${secret}\n`)
      assert.equal(right.exitCode, 0, `${template.id}: the emitted binary rejected its own accepted value`)
      assert.match(right.stdout, /accepted/)

      // A near miss must be rejected, and the loop must actually have run.
      const wrong = run(binary, `${secret.slice(0, -1)}${secret.slice(-1) === 'a' ? 'b' : 'a'}\n`)
      assert.equal(wrong.exitCode, 1, `${template.id}: the emitted binary accepted a near miss`)
      assert.match(wrong.stdout, /rejected/)

      // A wrong length fails the length gate before any comparison.
      const short = run(binary, `${secret.slice(0, -1)}\n`)
      assert.equal(short.exitCode, 1, `${template.id}: a short candidate was accepted`)

      // Empty input takes the no-input path.
      const empty = run(binary, '')
      assert.equal(empty.exitCode, 2, `${template.id}: empty input should report no input`)

      // The prompt and banner are printed before anything is read.
      assert.match(right.stdout, /Enter the accepted value:/)
      assert.match(right.stdout, new RegExp(template.id.split('-')[0]))
    }
  }
  // Named rather than counted, so a template that silently loses its emitter stops
  // the suite instead of quietly shrinking what is covered. `xor-loop` is the only
  // transform the deterministic emitter reproduces today; every other template
  // requires a compiler, and is marked `emittable: false` rather than shipped with a
  // fallback that answers differently from the verifier.
  assert.deepEqual(
    [...unemittable].sort(),
    ['arithmetic', 'branch', 'function-args', 'strcmp'],
    `unemittable templates changed: ${unemittable.join(', ')}`,
  )
  assert.ok(checked >= 1, `expected at least one emittable template, checked ${checked}`)
})

test('the emitter and the template predicate agree, variant by variant', () => {
  // The strongest statement available on this host: for random candidates, the
  // emitted program's exit status and the verifier's predicate must match. A
  // disagreement means a student could pass the binary and fail verification, or
  // the reverse.
  for (const template of templates.TEMPLATES) {
    const variant = template.variants.beginner
    if (!variant.emittable) continue
    const secret = templates.generateSecret(variant)
    const binary = elfBuilder.buildFallbackBinary(variant.transform(secret))

    const candidates = [
      secret,
      secret.toUpperCase(),
      secret.split('').reverse().join(''),
      variant.alphabet.slice(0, secret.length),
      `${secret}x`.slice(0, secret.length + 1),
    ]
    for (const candidate of candidates) {
      const programAccepted = run(binary, `${candidate}\n`).exitCode === 0
      const predicateAccepted = variant.accepts(secret, candidate)
      assert.equal(
        programAccepted,
        predicateAccepted,
        `${template.id}: program and predicate disagree on ${JSON.stringify(candidate)}`,
      )
    }
  }
})

test('emitted binaries are reproducible', () => {
  const variant = templates.findTemplate('xor-loop').variants.beginner
  const spec = variant.transform('deterministic')
  assert.deepEqual(elfBuilder.buildFallbackBinary(spec), elfBuilder.buildFallbackBinary(spec))
})
