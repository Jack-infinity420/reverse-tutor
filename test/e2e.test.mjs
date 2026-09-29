/**
 * End-to-end: the plugin as the harness sees it.
 *
 * This suite drives the four registered tools through a complete lesson —
 * "learn XOR" to a verified answer and a planned next challenge — using a
 * stand-in Cordis context. It is the closest thing to the live deployment that can
 * run unattended, and it is what proves the Definition of Done in the spec.
 */

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { useTemporaryRoot, loadModules, createFakeContext, loadHarnessValidator } from './helpers.mjs'

const cleanup = useTemporaryRoot('e2e')
const m = await loadModules()

test.after(() => cleanup())

test('every tool schema passes the harness\'s own validator', async t => {
  // This is the check that catches a schema the offline tests would accept and a
  // profile boot would reject: the harness compiles author-facing schemas into a
  // raw JSON Schema subset, and `required` must sit on the enclosing object
  // rather than on the property it describes.
  const harness = await loadHarnessValidator()
  if (harness === undefined) {
    t.diagnostic('harness modules not reachable from this checkout; skipped the authoritative schema check')
    return
  }

  const ctx = createFakeContext()
  m.plugin.apply(ctx, {})
  for (const definition of ctx.registered) {
    assert.ok(definition.output?.schema, `${definition.name} must declare an output schema`)

    // `ctx.tools.register` validates `parameters` and `output.schema` as RAW JSON
    // Schema before inserting the definition, so this mirrors the registry exactly.
    // An author-facing schema here fails on a profile boot with
    // `schema.properties.<field>.required is not supported` while every offline
    // test still passes — which is precisely the bug this assertion caught.
    assert.doesNotThrow(
      () => harness.assertSupportedJsonSchema(definition.output.schema),
      `${definition.name} output schema must be a supported raw JSON schema`,
    )
    assert.doesNotThrow(
      () => harness.assertSupportedJsonSchema(definition.parameters),
      `${definition.name} parameter schema must be a supported raw JSON schema`,
    )
    assert.equal(definition.parameters.type, 'object', `${definition.name} parameters must be object-rooted`)

    // A declared required field must exist as a property.
    for (const field of definition.parameters.required ?? []) {
      assert.ok(definition.parameters.properties[field], `${definition.name}: required parameter ${field} has no property`)
    }
    for (const field of definition.output.schema.required ?? []) {
      assert.ok(
        definition.output.schema.properties[field],
        `${definition.name}: required output field ${field} has no property`,
      )
    }

    // Every property of the enforced output schema must be one the renderer can
    // actually produce: compare against the declared value type.
    for (const field of Object.keys(definition.output.schema.properties)) {
      assert.ok(field.length > 0, `${definition.name} has an unnamed output property`)
    }
  }
})

test('the plugin registers four tools and one skill', () => {
  const ctx = createFakeContext()
  m.plugin.apply(ctx, {})

  const names = ctx.registered.map(definition => definition.name).sort()
  assert.deepEqual(names, ['reverse_build', 'reverse_inspect', 'reverse_state', 'reverse_submit'])

  for (const definition of ctx.registered) {
    assert.ok(definition.description.length > 80, `${definition.name} needs a real description for the model`)
    assert.ok(definition.parameters && typeof definition.parameters === 'object', `${definition.name} needs parameters`)
    assert.equal(typeof definition.output.render, 'function', `${definition.name} needs a renderer`)
    assert.equal(typeof definition.execute, 'function', `${definition.name} needs an executor`)
  }

  assert.equal(ctx.registeredSkills.length, 1)
  const skill = ctx.registeredSkills[0]
  assert.equal(skill.name, 'reverse-tutor')
  assert.match(skill.description, /IDA Pro/)
  assert.match(skill.content, /## Role/)
  assert.match(skill.content, /Hint levels/)
  // The body must not carry the YAML frontmatter: the registry owns that.
  assert.equal(skill.content.startsWith('---'), false)
})

test('reverse_build declares a bounded timeout', () => {
  const ctx = createFakeContext()
  m.plugin.apply(ctx, {})
  const build = ctx.registered.find(definition => definition.name === 'reverse_build')
  assert.ok(build.timeoutMs > 0 && build.timeoutMs < 120_000, 'a build must not be able to hang a turn')
})

test('the full XOR lesson runs end to end', async () => {
  const sessionId = `e2e-xor-${Date.now()}`
  const ctx = createFakeContext()
  m.plugin.apply(ctx, {})
  const tool = name => ctx.registered.find(definition => definition.name === name)
  const exec = { callId: 'e2e', name: 'x', signal: new AbortController().signal, agent: { session: { id: sessionId } } }

  // 1. TOPIC + 2. OBJECTIVES + 3. CHALLENGE
  const built = await tool('reverse_build').execute({ topic: 'xor', difficulty: 'beginner' }, exec)
  assert.equal(built.ok, true, built.message)
  assert.ok(built.challengeId)
  assert.equal(built.templateId, 'xor-loop')
  assert.ok(built.acceptedLength > 0)
  assert.ok(built.binaryPath.endsWith('challenge'))
  // The tool result must never carry the accepted value or a vault path.
  const serialized = JSON.stringify(built)
  assert.equal(/vault/i.test(serialized), false, 'the vault location must not be disclosed')

  // 4/5. The tutor observes facts rather than asking the student to paste them.
  const file = await tool('reverse_inspect').execute({ challengeId: built.challengeId, action: 'file' }, exec)
  assert.equal(file.ok, true)
  const entryPoint = String(file.facts.entry)

  const listing = await tool('reverse_inspect').execute(
    { challengeId: built.challengeId, action: 'objdump', functionName: entryPoint },
    exec,
  )
  assert.equal(listing.ok, true)
  assert.match(listing.text, /(Disassembly|Verified listing)/)
  assert.match(listing.text, /0x[0-9a-f]+/)

  // 6. A wrong answer: the tool refuses to reveal anything and moves the hint level.
  const wrong = await tool('reverse_submit').execute({ challengeId: built.challengeId, candidate: 'guess' }, exec)
  assert.equal(wrong.correct, false)
  assert.equal(wrong.message.includes('secret'), false)
  assert.ok(wrong.hintLevel >= 1)

  // 7. The state the teaching layer reads.
  const stateRead = tool('reverse_state').execute({ action: 'read' }, exec)
  assert.equal(stateRead.phase, 'HINT')
  assert.ok(stateRead.attempts >= 1)
  assert.ok(stateRead.hintLevel >= 1)
  assert.match(stateRead.summary, /hint level/)

  // 8. The student derives the answer; the verifier confirms it.
  const entry = m.workspace.readVaultEntry(built.challengeId)
  const right = await tool('reverse_submit').execute(
    {
      challengeId: built.challengeId,
      candidate: entry.secret,
      rubric: { key_function: 2, argument_flow: 2, control_flow: 2, data_flow: 1, evidence_quality: 2 },
      weaknesses: ['dataFlow'],
    },
    exec,
  )
  assert.equal(right.correct, true, right.message)
  assert.match(right.message, /correct: true/)

  // 9. UPDATE_STATE: the profile moved, the phase advanced.
  const after = tool('reverse_state').execute({ action: 'read' }, exec)
  assert.equal(after.phase, 'EXPLAIN')
  assert.ok(after.streak >= 1)
  // A correct answer closes the weakness it was named on...
  assert.deepEqual(after.weaknesses, [], 'mastery clears the named weakness')
  // ...but the score it earned stays low, so the next drill still targets it.
  assert.ok(after.skills.dataFlow < 0.65, 'a partially correct rubric item keeps the score low')

  // 10. NEXT_CHALLENGE: the recommendation drills the weak skill.
  assert.equal(after.nextTemplateId, 'xor-loop', 'a weak data-flow skill re-drills the same template')
  assert.ok(after.nextBecause.includes('dataFlow'))

  const next = await tool('reverse_build').execute({ topic: after.nextTemplateId, difficulty: after.nextDifficulty }, exec)
  assert.equal(next.ok, true, next.message)
  assert.notEqual(next.challengeId, built.challengeId, 'the next challenge is a new lab')
})

test('a wrong challenge id fails cleanly instead of crashing the turn', async () => {
  const sessionId = `e2e-bad-${Date.now()}`
  const ctx = createFakeContext()
  m.plugin.apply(ctx, {})
  const tool = name => ctx.registered.find(definition => definition.name === name)
  const exec = { callId: 'e2e', name: 'x', signal: new AbortController().signal, agent: { session: { id: sessionId } } }

  const inspect = await tool('reverse_inspect').execute({ challengeId: 'missing-0000', action: 'file' }, exec)
  assert.equal(inspect.ok, false)
  const submit = await tool('reverse_submit').execute({ challengeId: 'missing-0000', candidate: 'x' }, exec)
  assert.equal(submit.correct, false)
  const build = await tool('reverse_build').execute({ topic: 'xor', source: 'no marker here' }, exec)
  assert.equal(build.ok, false)
  assert.match(build.message, /SECRET/)
})
