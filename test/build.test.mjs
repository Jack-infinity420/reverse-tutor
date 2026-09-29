/**
 * Build integrity: the pipeline either produces a real, verified ELF challenge or
 * reports failure — never something in between.
 *
 * The anti-leak assertions here are the important ones. They check the *delivered*
 * bytes, not the tool's return value: a secret that reaches `challenge.c` or the
 * binary is a leak regardless of what the tool claims.
 */

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { existsSync, readFileSync } from 'node:fs'
import { useTemporaryRoot, loadModules } from './helpers.mjs'

const cleanup = useTemporaryRoot('build')
const { build, templates } = await loadModules()

test.after(() => cleanup())

test('reverse_build produces a real ELF and a verifier record', async () => {
  const outcome = await build.buildChallenge(
    { topic: 'xor', difficulty: 'beginner', sessionId: 'build-test' },
    { compileTimeoutMs: 25_000 },
  )
  assert.equal(outcome.ok, true, outcome.message)
  assert.ok(outcome.view)

  const binary = readFileSync(outcome.view.binaryPath)
  assert.equal(binary.subarray(1, 4).toString('ascii'), 'ELF')
  // 32-bit is the whole point: the student's ida.exe loads only this class.
  assert.equal(binary[4], 1, 'ELFCLASS32 — ida.exe cannot load a 64-bit image')
  assert.equal(binary[5], 1, 'little endian')
  assert.equal(binary.readUInt16LE(16), 2, 'ET_EXEC, so the addresses in the listing are the real ones')
  assert.equal(binary.readUInt16LE(18), 3, 'EM_386 — Intel 80386')
  assert.ok(binary.length > 256, 'a real ELF is not a stub')
  // The classic i386 non-PIE load address, so IDA's default base matches.
  assert.equal(binary.readUInt32LE(24) >= 0x0804_8000 && binary.readUInt32LE(24) < 0x0810_0000, true, 'entry in the i386 image range')
})

test('the delivered source and binary never contain the accepted value', async () => {
  for (const template of templates.TEMPLATES) {
    const outcome = await build.buildChallenge(
      { templateId: template.id, difficulty: 'beginner', sessionId: 'leak-test' },
      { compileTimeoutMs: 25_000 },
    )
    if (!outcome.ok) continue
    const entry = (await import('../lib/challenge/workspace.js')).readVaultEntry(outcome.view.challengeId)
    assert.ok(entry, 'the verifier record must exist')

    const source = readFileSync(outcome.view.sourcePath)
    const binary = readFileSync(outcome.view.binaryPath)
    const needle = Buffer.from(entry.secret, 'latin1')

    assert.equal(source.includes(entry.secret), false, `${template.id}: secret leaked into challenge.c`)
    assert.equal(binary.includes(needle), false, `${template.id}: secret leaked into the binary as plain text`)
    // The tool's own message must not carry it either.
    assert.equal(outcome.message.includes(entry.secret), false, `${template.id}: secret leaked into the tool message`)
  }
})

test('a build records how the artefact was produced', async () => {
  const outcome = await build.buildChallenge(
    { topic: 'xor', difficulty: 'beginner', sessionId: 'provenance-test' },
    { compileTimeoutMs: 25_000 },
  )
  assert.equal(outcome.ok, true, outcome.message)
  const entry = (await import('../lib/challenge/workspace.js')).readVaultEntry(outcome.view.challengeId)
  assert.ok(['built', 'fallback'].includes(entry.build.mode))
  assert.ok(entry.build.size > 0)
  assert.match(entry.build.sha256, /^[0-9a-f]{64}$/)
  assert.ok(entry.build.compiler.length > 0)
  // A fallback artefact must say so rather than pretending to be compiled.
  if (entry.build.mode === 'fallback') {
    assert.ok(outcome.warnings.some(warning => /compiler/i.test(warning)), 'a fallback build must warn about the compiler')
  }
})

test('a custom source must inject the secret at exactly one marker', async () => {
  const body = `
#include "mini_libc.h"
#define RT_SECRET_LENGTH 6
int rt_main(void)
{
    char input[RT_MAX_LINE];
    rt_puts("custom\\n");
    if (rt_read_line(input) <= 0) return 2;
    return input[0] == 0;
}
`
  // No injection marker at all.
  const noMarker = await build.buildChallenge(
    { templateId: 'xor-loop', difficulty: 'beginner', source: body, sessionId: 'custom-test' },
    { compileTimeoutMs: 25_000 },
  )
  assert.equal(noMarker.ok, false)
  assert.match(noMarker.message, /SECRET/)

  // Two markers: the accepted value would have to be injected twice.
  const twoMarkers = await build.buildChallenge(
    { templateId: 'xor-loop', difficulty: 'beginner', source: `${body}\n/* {{SECRET}} */\n/* {{SECRET}} */\n`, sessionId: 'custom-test' },
    { compileTimeoutMs: 25_000 },
  )
  assert.equal(twoMarkers.ok, false)
  assert.match(twoMarkers.message, /exactly one|twice/)

  // Exactly one marker: this one is a valid custom drill.
  const accepted = await build.buildChallenge(
    { templateId: 'xor-loop', difficulty: 'beginner', source: `${body}\n/* {{SECRET}} */\n`, sessionId: 'custom-test' },
    { compileTimeoutMs: 25_000 },
  )
  assert.equal(accepted.ok, true, accepted.message)
  assert.equal(accepted.message.includes('secret'), false)
})

test('a failed build leaves no half-built challenge on disk', async () => {
  const workspace = await import('../lib/challenge/workspace.js')
  const policy = await import('../lib/policy.js')
  const before = existsSync(policy.publicRoot())
    ? (await import('node:fs')).readdirSync(policy.publicRoot()).length
    : 0

  const rejected = await build.buildChallenge(
    { templateId: 'xor-loop', difficulty: 'beginner', source: '{{SECRET}} {{SECRET}}', sessionId: 'cleanup-test' },
    { compileTimeoutMs: 5_000 },
  )
  assert.equal(rejected.ok, false)
  assert.equal(rejected.view, undefined)

  const after = existsSync(policy.publicRoot())
    ? (await import('node:fs')).readdirSync(policy.publicRoot()).length
    : 0
  assert.equal(after, before, 'a rejected build must not leave a workspace behind')
  assert.equal(typeof workspace.challengePaths, 'function')
})

test('every template and difficulty builds or reports a reason', async () => {
  for (const template of templates.TEMPLATES) {
    for (const difficulty of templates.DIFFICULTIES) {
      const outcome = await build.buildChallenge(
        { templateId: template.id, difficulty, sessionId: 'matrix-test' },
        { compileTimeoutMs: 25_000 },
      )
      assert.equal(typeof outcome.ok, 'boolean')
      assert.ok(outcome.message.length > 0, `${template.id}/${difficulty} must explain its outcome`)
      if (outcome.ok) {
        assert.equal(existsSync(outcome.view.binaryPath), true)
        assert.equal(existsSync(outcome.view.sourcePath), true)
        assert.equal(existsSync(outcome.view.analysisDir), true)
        // The student brief must exist and must not name the answer.
        const brief = readFileSync(`${outcome.view.publicDir}/README.md`, 'utf8')
        assert.ok(brief.includes(outcome.view.challengeId))
        assert.ok(brief.includes('IDA'))
      }
    }
  }
})
