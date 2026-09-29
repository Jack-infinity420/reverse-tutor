/**
 * Inspection integrity: every action is bounded, path-safe, and truthful.
 *
 * The disassembler tests carry the most weight. A listing that is syntactically
 * valid but semantically reversed would teach a student something false, so the
 * decoder is checked against hand-verified encodings rather than against its own
 * output.
 */

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { useTemporaryRoot, loadModules } from './helpers.mjs'

const cleanup = useTemporaryRoot('inspect')
const { build, inspectTool, workspace, x86, inspectElf, objdump } = await loadModules()

test.after(() => cleanup())

/** Build one challenge and return its id. */
async function buildOne(templateId = 'xor-loop', difficulty = 'beginner') {
  const outcome = await build.buildChallenge({ templateId, difficulty, sessionId: 'inspect-test' }, { compileTimeoutMs: 25_000 })
  assert.equal(outcome.ok, true, outcome.message)
  return outcome.view.challengeId
}

test('file inspection reports the ELF facts and analysis anchors', async () => {
  const id = await buildOne()
  const result = await inspectTool.executeReverseInspect({ challengeId: id, action: 'file' })
  assert.equal(result.ok, true, result.text)
  assert.match(result.text, /ELF 32-bit/)
  assert.match(result.text, /Intel 80386/)
  assert.match(result.text, /ida\.exe/, 'the file view must say which IDA build opens it')
  assert.match(result.text, /EXEC/)
  assert.match(result.text, /entry point: 0x/)
  assert.equal(result.facts.entry.startsWith('0x'), true)
  assert.ok(result.facts.functions.length >= 1)
  // The entry the anchors name must resolve.
  const entryAddress = Number.parseInt(String(result.facts.entry), 16)
  assert.ok(entryAddress > 0)
})

test('strings inspection lists printable runs with offsets', async () => {
  const id = await buildOne()
  const result = await inspectTool.executeReverseInspect({ challengeId: id, action: 'strings' })
  assert.equal(result.ok, true)
  assert.match(result.text, /0x[0-9a-f]+/)
})

test('readelf inspection renders headers without leaking the answer', async () => {
  const id = await buildOne()
  const entry = workspace.readVaultEntry(id)
  const result = await inspectTool.executeReverseInspect({ challengeId: id, action: 'readelf' })
  assert.equal(result.ok, true)
  assert.match(result.text, /ELF Header:/)
  assert.match(result.text, /Program Headers:/)
  assert.match(result.text, /Section Headers:/)
  assert.equal(result.text.includes(entry.secret), false, 'readelf output must not contain the accepted value')
})

test('objdump resolves the entry point and never floods the context', async () => {
  const id = await buildOne()
  const entry = workspace.readVaultEntry(id)
  const info = inspectElf.parseElf(workspace.challengePaths(id).binaryPath)
  const result = await inspectTool.executeReverseInspect({
    challengeId: id,
    action: 'objdump',
    functionName: `0x${info.entry.toString(16)}`,
  })
  assert.equal(result.ok, true, result.text)
  assert.ok(result.text.length <= 12_000, 'output must respect the character budget')
  assert.equal(result.text.includes(entry.secret), false, 'a listing must not contain the accepted value')
})

test('objdump reports a usable error for an unknown function', async () => {
  const id = await buildOne()
  const result = await inspectTool.executeReverseInspect({ challengeId: id, action: 'objdump', functionName: 'not_a_function' })
  assert.equal(result.ok, false)
  assert.match(result.text, /no function matches/)
  assert.match(result.text, /0x/, 'the error must offer the anchors that do exist')
})

test('inspection rejects an unknown challenge id instead of guessing', async () => {
  const result = await inspectTool.executeReverseInspect({ challengeId: 'no-such-challenge-0000', action: 'file' })
  assert.equal(result.ok, false)
  assert.match(result.text, /unknown challengeId/)
})

test('inspection rejects a path-traversal challenge id', async () => {
  const result = await inspectTool.executeReverseInspect({ challengeId: '../../etc', action: 'file' })
  assert.equal(result.ok, false)
  assert.match(result.text, /challengeId|contain|parent/i)
})

test('ida_context explains itself when no export exists yet', async () => {
  const id = await buildOne()
  const result = await inspectTool.executeReverseInspect({ challengeId: id, action: 'ida_context' })
  assert.equal(result.ok, false)
  assert.match(result.text, /export/)
  assert.match(result.text, /bridge|IDA/)
})

test('ida_context reads a well-formed export', async () => {
  const id = await buildOne()
  const paths = workspace.challengePaths(id)
  const payload = {
    schema: 'reverse-tutor/ida-context/v1',
    binary: { name: 'challenge', architecture: '64' },
    cursor: { address: '0x4010E0' },
    currentFunction: { name: 'sub_4010E0', start: '0x4010E0', end: '0x401120' },
    assembly: [
      { address: '0x4010E0', text: 'movzx eax, byte ptr [rdi+rcx]' },
      { address: '0x4010E4', text: 'xor al, 37h' },
    ],
    pseudocode: 'int sub_4010E0(char *a1) { ... }',
    callers: ['main'],
    callees: [],
    strings: [],
    decompilerAvailable: true,
  }
  ;(await import('node:fs')).writeFileSync(paths.contextPath, JSON.stringify(payload), 'utf8')

  const result = await inspectTool.executeReverseInspect({ challengeId: id, action: 'ida_context' })
  assert.equal(result.ok, true, result.text)
  assert.match(result.text, /sub_4010E0/)
  assert.match(result.text, /xor al, 37h/)
  assert.match(result.text, /pseudocode/)
  assert.equal(result.facts.hasPseudocode, true)
})

test('ida_context tolerates an unparseable export', async () => {
  const id = await buildOne()
  const paths = workspace.challengePaths(id)
  ;(await import('node:fs')).writeFileSync(paths.contextPath, '{ not json', 'utf8')
  const result = await inspectTool.executeReverseInspect({ challengeId: id, action: 'ida_context' })
  assert.equal(result.ok, false)
  assert.match(result.text, /not valid JSON/)
})

test('bridge prints the exact steps the student needs', async () => {
  const id = await buildOne()
  const result = await inspectTool.executeReverseInspect({ challengeId: id, action: 'bridge' })
  assert.equal(result.ok, true)
  assert.match(result.text, /IDA Pro/)
  assert.match(result.text, /ida_context\.json/)
  assert.match(result.text, /cursor|Script file/i)
})

test('the decoder matches hand-verified encodings', () => {
  // Every expectation was verified byte for byte against llvm-objdump output for the
  // same bytes assembled for i386. These are 32-bit encodings, so 0x48 is `dec eax`
  // and 0x89e5 is `mov ebp, esp` — reading them with 64-bit eyes is exactly the
  // mistake this table exists to catch. Memory operands always carry their size, which
  // is what IDA's listing shows for the same bytes.
  const cases = [
    ['55', 'push', 'ebp'],
    ['89e5', 'mov', 'ebp, esp'],
    ['8b45f0', 'mov', 'eax, dword ptr [ebp - 0x10]'],
    ['8945f0', 'mov', 'dword ptr [ebp - 0x10], eax'],
    ['89c7', 'mov', 'edi, eax'],
    ['0fb6040f', 'movzx', 'eax, byte ptr [edi + ecx]'],
    ['8d85f0feffff', 'lea', 'eax, [ebp - 0x110]'],
    ['81ec10010000', 'sub', 'esp, 0x110'],
    ['83c001', 'add', 'eax, 0x1'],
    ['83f800', 'cmp', 'eax, 0x0'],
    ['e800000000', 'call', '0x1005'],
    ['cd80', 'int', '0x80'],
    ['f4', 'hlt', ''],
    ['c9', 'leave', ''],
    ['c3', 'ret', ''],
    ['48', 'dec', 'eax'],
  ]
  for (const [hex, mnemonic, operands] of cases) {
    const instruction = x86.decodeInstruction(Buffer.from(hex, 'hex'), 0x1000)
    assert.equal(instruction.length, hex.length / 2, `${hex} length`)
    assert.equal(instruction.mnemonic, mnemonic, `${hex} mnemonic`)
    assert.equal(instruction.operands, operands, `${hex} operands`)
  }
})

test('the decoder round-trips a continuous instruction stream', () => {
  // Walking the whole listing must consume exactly the bytes decoded: a length
  // that is one byte short desynchronises everything after it. These bytes are a
  // real i386 program prologue ending in the two-syscall exit sequence.
  //
  // The fixture is built from the per-instruction table rather than typed as one
  // long hex literal, because an odd-length literal makes Buffer.from silently drop
  // the final nibble and the stream then looks two bytes too long.
  const listing = [
    ['55', 'push', 'ebp'],
    ['89e5', 'mov', 'ebp, esp'],
    ['81ec10010000', 'sub', 'esp, 0x110'],
    ['e800000000', 'call', '0x804900e'],
    ['31ff', 'xor', 'edi, edi'],
    ['b83c000000', 'mov', 'eax, 0x3c'],
    ['cd80', 'int', '0x80'],
    ['f4', 'hlt', ''],
  ]
  const stream = Buffer.from(listing.map(entry => entry[0]).join(''), 'hex')
  assert.equal(stream.length, listing.reduce((sum, entry) => sum + entry[0].length / 2, 0))

  let offset = 0
  let count = 0
  while (offset < stream.length) {
    const instruction = x86.decodeInstruction(stream.subarray(offset), 0x8049000 + offset)
    assert.ok(instruction.length >= 1, 'every instruction consumes at least one byte')
    const expected = listing[count]
    assert.equal(instruction.length, expected[0].length / 2, `${expected[0]} length`)
    offset += instruction.length
    count += 1
    assert.ok(count <= listing.length, 'decoding must terminate')
  }
  assert.equal(count, listing.length, 'every instruction in the fixture must be decoded')
  assert.equal(offset, stream.length, 'the listing must consume the stream exactly')
})

test('disassembly stops at a terminal instruction rather than running on', async () => {
  const id = await buildOne()
  const info = inspectElf.parseElf(workspace.challengePaths(id).binaryPath)
  const block = objdump.decodeFunction(info, info.entry, { maxInstructions: 200 })
  const last = block.instructions[block.instructions.length - 1]
  assert.ok(last)
  assert.ok(
    ['ret', 'hlt', 'jmp'].includes(last.mnemonic) || block.instructions.length < 200,
    'a bounded function must end at a terminal instruction or the cap',
  )
})

test('every finding the inspector reports is derived from the actual file', async () => {
  const id = await buildOne()
  const info = inspectElf.parseElf(workspace.challengePaths(id).binaryPath)
  const result = await inspectTool.executeReverseInspect({ challengeId: id, action: 'file' })
  assert.equal(result.facts.size, info.size)
  assert.equal(result.facts.segments, info.segments.length)
  assert.equal(result.facts.sections, info.sections.length)
})
