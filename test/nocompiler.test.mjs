/**
 * The compiler-free path, exercised against a host that has no usable compiler.
 *
 * Two rules are under test, and the second is the important one:
 *
 * 1. `DSH_REVERSE_TUTOR_ALLOW_EMITTER` still produces a verified, runnable ELF
 *    challenge on a host with no Linux-capable compiler.
 * 2. Without that switch, a host that cannot compile **fails the build** instead of
 *    quietly shipping the emitted blob. An emitted artefact has no C function
 *    structure — no prologues, no cross-function calls, no cdecl frame — so a silent
 *    downgrade to it turns a toolchain problem into a lesson with nothing to analyse.
 *
 * The LLVM directory is temporarily renamed for the duration of this test, which is
 * the only honest way to reproduce a host without a Linux-capable toolchain. It lives
 * in its own file so it never races the suites that do need a compiler.
 */

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync, rmSync } from 'node:fs'
import { join } from 'node:path'
import { useTemporaryRoot, loadModules } from './helpers.mjs'

const cleanup = useTemporaryRoot('nocc')
const m = await loadModules()

/**
 * Point `DSH_REVERSE_TUTOR_CC` at a program that exists but cannot compile.
 *
 * This is the deterministic way to model "no usable compiler": detection probes the
 * override first, the probe fails, and every auto-detected candidate is then skipped
 * by the same probe. It needs no permission on `Program Files`, unlike moving a real
 * LLVM installation aside.
 */
function unusableCompilerPath() {
  return process.platform === 'win32'
    ? join(process.env['SystemRoot'] ?? 'C:\\Windows', 'System32', 'cmd.exe')
    : '/bin/false'
}

test.after(() => {
  cleanup()
})

/** Put the host into "no usable compiler" for the duration of `body`. */
async function withoutCompiler(body) {
  const saved = {
    cc: process.env['DSH_REVERSE_TUTOR_CC'],
    programFiles: process.env['ProgramFiles'],
    localAppData: process.env['LOCALAPPDATA'],
    path: process.env['PATH'],
  }
  // Both halves matter: the override makes the explicit candidate unusable, and the
  // environment makes every auto-detected candidate unreachable — an absolute
  // `Program Files\LLVM` path that does not exist is skipped, and a PATH without
  // clang or gcc leaves nothing to fall back to.
  process.env['DSH_REVERSE_TUTOR_CC'] = unusableCompilerPath()
  process.env['ProgramFiles'] = 'C:\\Program Files (not-here)'
  process.env['LOCALAPPDATA'] = 'C:\\not-here'
  process.env['PATH'] = process.platform === 'win32' ? 'C:\\Windows\\System32' : '/nonexistent-bin'
  m.toolchain.resetToolchainCache()
  const forced = m.toolchain.detectToolchain() === undefined
  try {
    return await body(forced)
  } finally {
    for (const [key, value] of [
      ['DSH_REVERSE_TUTOR_CC', saved.cc],
      ['ProgramFiles', saved.programFiles],
      ['LOCALAPPDATA', saved.localAppData],
      ['PATH', saved.path],
    ]) {
      if (value === undefined) delete process.env[key]
      else process.env[key] = value
    }
    m.toolchain.resetToolchainCache()
  }
}

test('a host with no compiler fails the build instead of emitting a silent substitute', async t => {
  await withoutCompiler(async forced => {
    delete process.env['DSH_REVERSE_TUTOR_ALLOW_EMITTER']
    m.toolchain.resetToolchainCache()
    if (!forced) {
      t.diagnostic('a compiler is still reachable on this host; the failure path could not be forced')
      return
    }
    const outcome = await m.build.buildChallenge(
      { templateId: 'xor-loop', difficulty: 'beginner', sessionId: 'nocc-test' },
      { compileTimeoutMs: 15_000 },
    )
    assert.equal(outcome.ok, false, 'an unbuildable challenge must not be presented')
    assert.match(outcome.message, /compiler/i)
    assert.match(outcome.message, /ALLOW_EMITTER/, 'the message must name the switch that re-enables emitting')
  })
})

test('the emitter, when switched on, still delivers a verified ELF challenge', async t => {
  await withoutCompiler(async forced => {
    process.env['DSH_REVERSE_TUTOR_ALLOW_EMITTER'] = '1'
    m.toolchain.resetToolchainCache()
    try {
      const outcome = await m.build.buildChallenge(
        { templateId: 'xor-loop', difficulty: 'beginner', sessionId: 'nocc-test' },
        { compileTimeoutMs: 15_000 },
      )
      assert.equal(outcome.ok, true, outcome.message)
      if (!forced) t.diagnostic('a compiler was still reachable; the compiled path was exercised instead')

      const binary = readFileSync(outcome.view.binaryPath)
      assert.equal(binary.subarray(1, 4).toString('ascii'), 'ELF')
      assert.equal(binary[4], 1, 'ELFCLASS32 — the whole point of the target choice')
      assert.equal(binary.readUInt16LE(16), 2, 'ET_EXEC')
      assert.equal(binary.readUInt16LE(18), 3, 'EM_386')

      if (outcome.view.buildMode === 'fallback') {
        assert.ok(
          outcome.warnings.some(warning => /compiler/i.test(warning)),
          `a fallback build must say so; warnings were: ${outcome.warnings.join(' | ')}`,
        )
      } else {
        t.diagnostic('a compiler was reachable on this host; the compiled path was exercised instead')
      }

      // The verifier must accept the value whichever tier answers.
      const entry = m.workspace.readVaultEntry(outcome.view.challengeId)
      const verdict = await m.verifier.verifySubmission({
        entry,
        binaryPath: outcome.view.binaryPath,
        candidate: entry.secret,
        attempts: 1,
        timeoutMs: 5_000,
      })
      assert.equal(verdict.correct, true, 'the opt-in path must still be completable')

      // And the inspector must still be able to read it — and must say which IDA
      // build opens it, because a 32-bit-only IDA cannot load anything else.
      const inspected = await m.inspectTool.executeReverseInspect({ challengeId: outcome.view.challengeId, action: 'file' })
      assert.equal(inspected.ok, true, inspected.text)
      assert.match(inspected.text, /ELF 32-bit/)
      assert.match(inspected.text, /Intel 80386/)
      assert.match(inspected.text, /ida\.exe/)

      rmSync(outcome.view.publicDir, { recursive: true, force: true })
    } finally {
      delete process.env['DSH_REVERSE_TUTOR_ALLOW_EMITTER']
    }
  })
})

test('the deterministic emitter refuses a variant it cannot reproduce', async () => {
  // `function-args` uses cross-function digests with no bytewise equivalent, so
  // its spec carries length 0 and the emitter must reject it rather than emit a
  // program that accepts the empty string.
  const template = m.templates.findTemplate('function-args')
  assert.equal(template.variants.beginner.emittable, false)
  const secret = m.templates.generateSecret(template.variants.beginner)
  const spec = template.variants.beginner.transform(secret)
  assert.throws(() => m.elfBuilder.buildFallbackBinary(spec), /cannot represent|compiler is required/)
})
