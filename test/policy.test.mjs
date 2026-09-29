/**
 * policy.test.ts equivalent: path containment, limits, and tool safety.
 *
 * The path tests are the security-relevant ones: every one of them attempts a real
 * escape through a name that would otherwise become a filesystem path.
 */

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { join, sep } from 'node:path'
import { useTemporaryRoot, loadModules } from './helpers.mjs'

const cleanup = useTemporaryRoot('policy')
const m = await loadModules()
const { policy } = m

test.after(() => cleanup())

test('resolveInside accepts a plain child name', () => {
  const root = policy.tutorRoot()
  assert.equal(policy.resolveInside(root, 'challenge'), join(root, 'challenge'))
})

test('resolveInside rejects a parent-directory escape', () => {
  const root = policy.tutorRoot()
  assert.throws(() => policy.resolveInside(root, '../../../../etc/passwd'), /escapes its allowed root/)
  assert.throws(() => policy.resolveInside(root, '..'), /escapes its allowed root/)
  assert.throws(() => policy.resolveInside(root, 'a/../../b'), /escapes its allowed root/)
})

test('resolveInside rejects an absolute path outside the root', () => {
  const root = policy.tutorRoot()
  const outside = process.platform === 'win32' ? 'C:\\Windows\\win.ini' : '/etc/passwd'
  assert.throws(() => policy.resolveInside(root, outside), /escapes its allowed root/)
})

test('resolveInside rejects NUL and empty names', () => {
  const root = policy.tutorRoot()
  assert.throws(() => policy.resolveInside(root, ''), /non-empty/)
  assert.throws(() => policy.resolveInside(root, 'a\0b'), /NUL/)
})

test('resolveInside does not treat a sibling prefix as inside', () => {
  // `<root>-evil` shares a string prefix with `<root>` but is a different path.
  const root = policy.tutorRoot()
  assert.throws(() => policy.resolveInside(root, `..${sep}${root.split(sep).pop()}-evil`), /escapes/)
})

test('assertSafeSegment rejects traversal and odd characters', () => {
  assert.equal(policy.assertSafeSegment('xor-loop-20260101-000000-ab12', 'challengeId'), 'xor-loop-20260101-000000-ab12')
  // Topic-named folders: CJK and interior spaces are fine on NTFS.
  assert.equal(policy.assertSafeSegment('构造函数与析构函数challenge', 'challengeId'), '构造函数与析构函数challenge')
  assert.equal(policy.assertSafeSegment('构造函数与析构函数challenge-2', 'challengeId'), '构造函数与析构函数challenge-2')
  assert.equal(policy.assertSafeSegment('a b', 'challengeId'), 'a b')
  assert.throws(() => policy.assertSafeSegment('..', 'challengeId'), /parent-directory|path separators/)
  assert.throws(() => policy.assertSafeSegment('a/../b', 'challengeId'), /path separators|parent-directory/)
  assert.throws(() => policy.assertSafeSegment('a\\b', 'challengeId'), /path separators/)
  assert.throws(() => policy.assertSafeSegment('a<b', 'challengeId'), /illegal in a file name/)
  assert.throws(() => policy.assertSafeSegment('a\0b', 'challengeId'), /illegal in a file name/)
  assert.throws(() => policy.assertSafeSegment('a.', 'challengeId'), /dot or a space/)
  assert.throws(() => policy.assertSafeSegment('a ', 'challengeId'), /dot or a space/)
  assert.throws(() => policy.assertSafeSegment('', 'challengeId'), /non-empty/)
  assert.throws(() => policy.assertSafeSegment('a'.repeat(200), 'challengeId'), /too long/)
})

test('clampText truncates and says so', () => {
  const short = policy.clampText('abc', 100)
  assert.equal(short, 'abc')
  const long = policy.clampText('x'.repeat(500), 200)
  assert.ok(long.length < 500)
  assert.match(long, /output truncated/)
})

test('writeFileAtomic replaces content and leaves no temp file', () => {
  const path = join(policy.tutorRoot(), 'atomic.json')
  policy.writeFileAtomic(path, '{"a":1}')
  policy.writeJsonAtomic(path, { a: 2 })
  const read = policy.readJson(path)
  assert.deepEqual(read, { a: 2 })
})

test('default limits match the documented budget', () => {
  assert.equal(policy.DEFAULT_LIMITS.maxOutputChars, 12_000)
  assert.ok(policy.DEFAULT_LIMITS.compileTimeoutMs >= 1_000)
  assert.ok(policy.DEFAULT_LIMITS.submitTimeoutMs >= 1_000)
  assert.ok(policy.DEFAULT_LIMITS.maxCandidateChars <= 1_024)
})

test('tutorRoot honours the environment override and stays outside the cwd', () => {
  assert.equal(policy.tutorRoot(), process.env['DSH_REVERSE_TUTOR_ROOT'])
  assert.ok(policy.vaultRoot().startsWith(policy.tutorRoot()))
  assert.ok(policy.publicRoot().startsWith(policy.tutorRoot()))
  assert.notEqual(policy.publicRoot(), policy.vaultRoot())
})
