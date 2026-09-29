/**
 * Verification integrity and the learning state machine.
 *
 * Three properties are load-bearing and every test below is really about one of
 * them: the verdict is deterministic, the verdict never leaks the answer, and the
 * state only moves in ways the teaching policy can rely on.
 */

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { useTemporaryRoot, loadModules } from './helpers.mjs'

const cleanup = useTemporaryRoot('submit')
const { build, submitTool, stateTool, workspace, verifier } = await loadModules()

test.after(() => cleanup())

async function buildOne(templateId = 'xor-loop', difficulty = 'beginner') {
  const outcome = await build.buildChallenge({ templateId, difficulty, sessionId: 'submit-test' }, { compileTimeoutMs: 25_000 })
  assert.equal(outcome.ok, true, outcome.message)
  return outcome.view.challengeId
}

test('the accepted value verifies and a near miss does not', async () => {
  const id = await buildOne()
  const entry = workspace.readVaultEntry(id)

  const right = await submitTool.executeReverseSubmit({ challengeId: id, candidate: entry.secret }, { sessionId: 'submit-test' })
  assert.equal(right.correct, true, `the generated answer must verify: ${right.message}`)
  assert.ok(['executed', 'executed-foreign', 'predicate'].includes(right.decision))

  const wrong = await submitTool.executeReverseSubmit({ challengeId: id, candidate: `${entry.secret}x` }, { sessionId: 'submit-test' })
  assert.equal(wrong.correct, false)
  assert.ok(wrong.attempts >= 2, 'the attempt counter must advance per submission')
})

test('no answer-bearing value ever reaches the tool result', async () => {
  const id = await buildOne()
  const entry = workspace.readVaultEntry(id)
  const value = await submitTool.executeReverseSubmit(
    { challengeId: id, candidate: `${entry.secret}x` },
    { sessionId: 'submit-test' },
  )
  const serialized = JSON.stringify(value)
  assert.equal(serialized.includes(entry.secret), false, 'the accepted value must not appear in the result')
  assert.equal(serialized.includes(entry.answerFingerprint), false, 'the fingerprint must not appear either')
  assert.equal(/secret/i.test(serialized), false, 'the result must not even mention a secret field')
  for (const key of Object.keys(value)) {
    assert.ok(
      ['correct', 'attempts', 'decision', 'reason', 'acceptedLength', 'submittedLength', 'hintLevel', 'message', 'nextSteps'].includes(key),
      `unexpected result field: ${key}`,
    )
  }
})

test('submission rejects an unknown challenge and an over-long candidate', async () => {
  const unknown = await submitTool.executeReverseSubmit({ challengeId: 'nope-0000', candidate: 'x' }, { sessionId: 'submit-test' })
  assert.equal(unknown.correct, false)
  assert.equal(unknown.reason, 'unknown_challenge')

  const id = await buildOne()
  const tooLong = await submitTool.executeReverseSubmit(
    { challengeId: id, candidate: 'x'.repeat(5_000) },
    { sessionId: 'submit-test' },
  )
  assert.equal(tooLong.correct, false)
  assert.equal(tooLong.reason, 'candidate_too_long')
})

test('submission rejects a path-traversal challenge id', async () => {
  const result = await submitTool.executeReverseSubmit({ challengeId: '../../vault', candidate: 'x' }, { sessionId: 'submit-test' })
  assert.equal(result.correct, false)
  assert.equal(result.decision, 'rejected')
})

test('candidate normalisation removes only surface noise', async () => {
  const id = await buildOne()
  const entry = workspace.readVaultEntry(id)

  // Trailing newline, quotes, and surrounding whitespace are accepted.
  const noisy = await submitTool.executeReverseSubmit(
    { challengeId: id, candidate: `  "${entry.secret}"\n` },
    { sessionId: 'submit-test' },
  )
  assert.equal(noisy.correct, true, 'surface noise must be tolerated')

  // Nothing else is normalised: a single changed character still fails.
  const mutated = `${entry.secret.slice(0, -1)}${entry.secret.slice(-1) === 'a' ? 'b' : 'a'}`
  const wrong = await submitTool.executeReverseSubmit({ challengeId: id, candidate: mutated }, { sessionId: 'submit-test' })
  assert.equal(wrong.correct, false)

  const normalized = verifier.normalizeCandidate('  "abc" \n')
  assert.equal(normalized.value, 'abc')
  assert.equal(normalized.changed, true)
  assert.equal(verifier.normalizeCandidate('abc').changed, false)
})

test('the template predicate and the binary agree on the accepted value', async () => {
  // Whichever tier answers, the answer is the same. This is what makes the
  // predicate a legitimate fallback on a host that cannot run the ELF.
  for (const templateId of ['xor-loop', 'strcmp', 'arithmetic', 'branch']) {
    const id = await buildOne(templateId)
    const entry = workspace.readVaultEntry(id)
    const executed = await submitTool.executeReverseSubmit({ challengeId: id, candidate: entry.secret }, { sessionId: 'tier-test' })
    const predicate = await submitTool.executeReverseSubmit(
      { challengeId: id, candidate: entry.secret, noExecute: true },
      { sessionId: 'tier-test' },
    )
    assert.equal(executed.correct, true, `${templateId} should verify`)
    assert.equal(predicate.correct, true, `${templateId} predicate should verify`)
    assert.equal(predicate.decision, 'predicate')
  }
})

test('the verifier never calls a model', async () => {
  // Structural guarantee: strip comments, then assert the module mentions no
  // network or LLM surface at all.
  const raw = await import('node:fs').then(fs => fs.readFileSync('src/verifier.ts', 'utf8'))
  const code = raw.replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/.*$/gm, '')
  for (const forbidden of ['fetch', 'http', 'openai', 'anthropic', 'llm']) {
    assert.equal(code.toLowerCase().includes(forbidden), false, `verifier.ts must not reference ${forbidden}`)
  }
})

test('the hint level moves up on failure and never down', async () => {
  const sessionId = `hint-test-${Date.now()}`
  const id = await buildOne()
  const entry = workspace.readVaultEntry(id)

  let first = await submitTool.executeReverseSubmit({ challengeId: id, candidate: 'definitely-wrong' }, { sessionId })
  assert.equal(first.hintLevel, 1)
  const second = await submitTool.executeReverseSubmit({ challengeId: id, candidate: 'also-wrong' }, { sessionId })
  assert.equal(second.hintLevel, 2)

  const raised = stateTool.executeReverseState({ action: 'hint', delta: 10 }, { sessionId })
  assert.equal(raised.hintLevel, 5, 'the level is capped')
  const lowered = stateTool.executeReverseState({ action: 'hint', delta: -10 }, { sessionId })
  assert.equal(lowered.hintLevel, 0, 'and floored')

  // A correct answer must not raise it further.
  stateTool.executeReverseState({ action: 'hint', delta: 2 }, { sessionId })
  const correct = await submitTool.executeReverseSubmit({ challengeId: id, candidate: entry.secret }, { sessionId })
  assert.equal(correct.correct, true)
  const after = stateTool.executeReverseState({ action: 'read' }, { sessionId })
  assert.ok(after.hintLevel <= 2)
})

test('a rubric moves the skill profile and an absent rubric does not', async () => {
  const sessionId = `rubric-test-${Date.now()}`
  const id = await buildOne()
  const entry = workspace.readVaultEntry(id)

  const before = stateTool.executeReverseState({ action: 'read' }, { sessionId })
  const baselineDataFlow = before.skills.dataFlow

  const graded = await submitTool.executeReverseSubmit(
    {
      challengeId: id,
      candidate: entry.secret,
      rubric: { key_function: 2, argument_flow: 2, control_flow: 2, data_flow: 2, evidence_quality: 2 },
    },
    { sessionId },
  )
  assert.equal(graded.correct, true)
  const after = stateTool.executeReverseState({ action: 'read' }, { sessionId })
  assert.ok(after.skills.dataFlow > baselineDataFlow, 'a perfect rubric must raise the skill score')

  // An out-of-range rubric must be ignored, not clamped to an extreme.
  const ignored = stateTool.executeReverseState({ action: 'skill', skill: 'dataFlow', score: 5 }, { sessionId })
  assert.equal(ignored.ok, false)
  const bogus = stateTool.executeReverseState({ action: 'skill', skill: 'notASkill', score: 0.5 }, { sessionId })
  assert.equal(bogus.ok, false)
})

test('weaknesses are recorded, deduplicated, and cleared on mastery', async () => {
  const sessionId = `weak-test-${Date.now()}`
  const id = await buildOne()
  const entry = workspace.readVaultEntry(id)

  const wrong = await submitTool.executeReverseSubmit(
    { challengeId: id, candidate: 'wrong', weaknesses: ['dataFlow', 'dataFlow', 'notASkill'] },
    { sessionId },
  )
  assert.equal(wrong.correct, false)
  const recorded = stateTool.executeReverseState({ action: 'read' }, { sessionId })
  assert.deepEqual(recorded.weaknesses, ['dataFlow'], 'only tracked skills are kept, without duplicates')

  const right = await submitTool.executeReverseSubmit(
    { challengeId: id, candidate: entry.secret, weaknesses: ['dataFlow'] },
    { sessionId },
  )
  assert.equal(right.correct, true)
  const cleared = stateTool.executeReverseState({ action: 'read' }, { sessionId })
  assert.deepEqual(cleared.weaknesses, [], 'a correct answer with the weakness named clears it')
})

test('the state recommends a next challenge from the profile', async () => {
  const sessionId = `plan-test-${Date.now()}`
  stateTool.executeReverseState({ action: 'skill', skill: 'controlFlow', score: 0 }, { sessionId })
  stateTool.executeReverseState({ action: 'weaknesses', weaknesses: ['controlFlow'] }, { sessionId })
  const planned = stateTool.executeReverseState({ action: 'read' }, { sessionId })
  assert.equal(planned.nextTemplateId, 'branch', 'a weak control-flow skill drills the branch template')
  assert.match(planned.nextBecause, /controlFlow/)

  stateTool.executeReverseState({ action: 'skill', skill: 'controlFlow', score: 1 }, { sessionId })
  stateTool.executeReverseState({ action: 'weaknesses', weaknesses: [] }, { sessionId })
  const advanced = stateTool.executeReverseState({ action: 'read' }, { sessionId })
  assert.ok(advanced.nextTemplateId)
  assert.ok(advanced.nextBecause.length > 0)
})

test('state survives a malformed file', async () => {
  const sessionId = `robust-test-${Date.now()}`
  const policy = await import('../lib/policy.js')
  const state = await import('../lib/state.js')
  const path = state.statePath(sessionId)
  ;(await import('node:fs')).mkdirSync(policy.stateRoot(), { recursive: true })
  ;(await import('node:fs')).writeFileSync(path, '{"version":1,"hintLevel":"lots","skills":{"dataFlow":"high"},"phase":"BOGUS"}', 'utf8')

  const loaded = state.loadState(sessionId)
  assert.equal(loaded.hintLevel, 0, 'a non-numeric hint level degrades to 0')
  assert.equal(typeof loaded.skills.dataFlow, 'number')
  assert.equal(loaded.phase, 'IDLE', 'an unknown phase degrades to IDLE')
  assert.equal(Array.isArray(loaded.weaknesses), true)
})

test('state files stay outside the challenge workspace', async () => {
  const policy = await import('../lib/policy.js')
  const state = await import('../lib/state.js')
  const path = state.statePath('isolation-test')
  assert.ok(path.startsWith(policy.stateRoot()))
  assert.equal(path.startsWith(policy.publicRoot()), false)
  assert.equal(path.startsWith(policy.vaultRoot()), false)
})
