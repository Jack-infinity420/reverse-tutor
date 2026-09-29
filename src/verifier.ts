/**
 * The deterministic verifier.
 *
 * It answers exactly one question \u2014 "is this the accepted value?" \u2014 and it never
 * calls a model. Three properties matter and are all enforced here:
 *
 * 1. **Never leaks the answer.** The only value that leaves this module towards
 *    the model is a boolean, an attempt counter, and a coarse reason code. The
 *    accepted value is compared inside the process and is never returned, echoed,
 *    or embedded in an error message.
 * 2. **Never trusts caller input as the verdict.** Tier 1 executes the built
 *    binary and requires a real exit code; tiers 2 and 3 fall back to the
 *    template predicate, which is package-owned code, never model-supplied text.
 * 3. **Survives a missing runtime.** On a host that cannot execute a Linux ELF
 *    at all, tier 3 still produces a trustworthy verdict, and the tier that
 *    produced it is reported so the teaching layer can be honest about it.
 *
 * @module dsh-reverse-tutor/verifier
 */

import { existsSync } from 'node:fs'
import { findTemplate } from './challenge/templates.js'
import type { Difficulty } from './challenge/templates.js'
import { detectRuntime, runProcess } from './challenge/toolchain.js'
import type { VaultEntry } from './challenge/workspace.js'
import { clampText } from './policy.js'

/** Which mechanism produced the verdict. */
export type VerdictTier = 'executed' | 'executed-foreign' | 'predicate'

/** Why a submission was rejected, at a granularity that never reveals content. */
export type RejectionReason =
  | 'length_mismatch'
  | 'content_mismatch'
  | 'crash'
  | 'timeout'
  | 'no_candidate'

/** The verifier's answer. Contains no reference to the accepted value. */
export interface Verdict {
  readonly correct: boolean
  readonly tier: VerdictTier
  readonly attempts: number
  /** Coarse diagnosis, useful for choosing a hint level. */
  readonly reason: RejectionReason
  /** Accepted length; shape information the brief already discloses. */
  readonly acceptedLength: number
  /** Candidate length as submitted, before normalisation. */
  readonly submittedLength: number
  /** One line about the tier, safe to show the student. */
  readonly note: string
}

/** Candidate normalisation result. */
export interface NormalizedCandidate {
  readonly value: string
  readonly changed: boolean
  readonly notes: readonly string[]
}

/**
 * Normalise a submitted candidate before comparison.
 *
 * Only surface noise is removed: surrounding whitespace, one layer of matching
 * quotes, and a single trailing newline. Nothing here changes what the value
 * *is* \u2014 a wrong answer stays wrong.
 */
export function normalizeCandidate(raw: string): NormalizedCandidate {
  const notes: string[] = []
  let value = typeof raw === 'string' ? raw : String(raw ?? '')
  const original = value

  if (value.endsWith('\r\n')) {
    value = value.slice(0, -2)
    notes.push('stripped a trailing CRLF')
  } else if (value.endsWith('\n') || value.endsWith('\r')) {
    value = value.slice(0, -1)
    notes.push('stripped a trailing newline')
  }

  const trimmed = value.trim()
  if (trimmed !== value) {
    value = trimmed
    notes.push('trimmed surrounding whitespace')
  }

  const quotePairs: [string, string][] = [
    ['"', '"'],
    ["'", "'"],
    ['`', '`'],
    ['\u201c', '\u201d'],
  ]
  for (const [open, close] of quotePairs) {
    if (value.length >= 2 && value.startsWith(open) && value.endsWith(close)) {
      value = value.slice(1, -1)
      notes.push('removed surrounding quotes')
      break
    }
  }

  return { value, changed: value !== original, notes }
}

/** Execute the built challenge with `candidate` on stdin and read its exit code. */
async function executeChallenge(
  entry: VaultEntry,
  binaryPath: string,
  candidate: string,
  timeoutMs: number,
): Promise<{ tier: VerdictTier; reason: RejectionReason; correct: boolean; note: string } | undefined> {
  if (!existsSync(binaryPath)) return undefined
  const runtime = detectRuntime()
  if (runtime === undefined) return undefined

  let command = binaryPath
  let args: string[] = []
  let cwd: string | undefined

  if (runtime.kind === 'wsl') {
    // WSL cannot execute a Windows path; translate D:\x to /mnt/d/x.
    command = runtime.command ?? 'wsl.exe'
    const translated = toWslPath(binaryPath)
    args = [...(runtime.prefixArgs ?? ['-e']), translated]
    cwd = undefined
  } else if (runtime.kind === 'qemu') {
    command = runtime.command ?? 'qemu-i386'
    args = [binaryPath]
    cwd = undefined
  } else {
    args = []
    cwd = undefined
  }

  const result = await runProcess(command, args, {
    timeoutMs,
    maxOutputChars: 4_000,
    ...(cwd === undefined ? {} : { cwd }),
    stdin: `${candidate}\n`,
  })

  if (result.timedOut) {
    return {
      tier: runtime.kind === 'native' ? 'executed' : 'executed-foreign',
      reason: 'timeout',
      correct: false,
      note: `the challenge binary did not finish within ${timeoutMs} ms`,
    }
  }
  if (result.spawnError !== undefined) return undefined
  if (result.signal !== null) {
    return {
      tier: runtime.kind === 'native' ? 'executed' : 'executed-foreign',
      reason: 'crash',
      correct: false,
      note: 'the challenge binary terminated on a signal instead of returning an exit code',
    }
  }
  const exitCode = result.code ?? 1
  if (exitCode === 0) {
    return {
      tier: runtime.kind === 'native' ? 'executed' : 'executed-foreign',
      reason: 'content_mismatch',
      correct: true,
      note: `verified by executing the challenge (${runtime.label}), exit code 0`,
    }
  }
  if (exitCode === 2) {
    return {
      tier: runtime.kind === 'native' ? 'executed' : 'executed-foreign',
      reason: 'no_candidate',
      correct: false,
      note: 'the challenge binary read no input',
    }
  }
  return {
    tier: runtime.kind === 'native' ? 'executed' : 'executed-foreign',
    reason: candidate.length === entry.answerLength ? 'content_mismatch' : 'length_mismatch',
    correct: false,
    note: `verified by executing the challenge (${runtime.label}), exit code ${exitCode}`,
  }
}

/** Translate a Windows path into its WSL `/mnt/<drive>` form. */
export function toWslPath(path: string): string {
  const match = /^([A-Za-z]):[\\/](.*)$/.exec(path)
  if (match === null) return path.replace(/\\/g, '/')
  const drive = match[1]!.toLowerCase()
  return `/mnt/${drive}/${match[2]!.replace(/\\/g, '/')}`
}

/** Decide one submission. Never returns the accepted value. */
export async function verifySubmission(options: {
  readonly entry: VaultEntry
  readonly binaryPath: string
  readonly candidate: string
  readonly attempts: number
  readonly timeoutMs: number
  /** Force the predicate tier; used by tests and by `--no-exec`. */
  readonly forcePredicate?: boolean
}): Promise<Verdict> {
  const { entry, binaryPath, attempts, timeoutMs } = options
  const normalized = normalizeCandidate(options.candidate)
  const template = findTemplate(entry.templateId)
  const variant = template?.variants[entry.difficulty as Difficulty]

  if (normalized.value.length === 0) {
    return {
      correct: false,
      tier: 'predicate',
      attempts,
      reason: 'no_candidate',
      acceptedLength: entry.answerLength,
      submittedLength: 0,
      note: 'empty submission rejected before verification',
    }
  }

  // Tier 1/2: the binary is the ground truth whenever this host can run it.
  if (options.forcePredicate !== true) {
    const executed = await executeChallenge(entry, binaryPath, normalized.value, timeoutMs)
    if (executed !== undefined) {
      return {
        correct: executed.correct,
        tier: executed.tier,
        attempts,
        reason: executed.correct
          ? executed.reason
          : normalized.value.length !== entry.answerLength
            ? 'length_mismatch'
            : executed.reason,
        acceptedLength: entry.answerLength,
        submittedLength: normalized.value.length,
        note: executed.note,
      }
    }
  }

  // Tier 3: the template predicate. Package-owned code, deterministic, and
  // available on every host.
  if (variant === undefined) {
    return {
      correct: false,
      tier: 'predicate',
      attempts,
      reason: 'content_mismatch',
      acceptedLength: entry.answerLength,
      submittedLength: normalized.value.length,
      note: `template ${entry.templateId}/${entry.difficulty} cannot be re-derived on this host`,
    }
  }

  const lengthMatches = normalized.value.length === entry.answerLength
  const accepted = variant.accepts(entry.secret, normalized.value)
  return {
    correct: accepted,
    tier: 'predicate',
    attempts,
    reason: accepted ? 'content_mismatch' : lengthMatches ? 'content_mismatch' : 'length_mismatch',
    acceptedLength: entry.answerLength,
    submittedLength: normalized.value.length,
    note: accepted
      ? 'verified against the template predicate (no Linux runtime available on this host)'
      : 'checked against the template predicate; the value did not satisfy the challenge',
  }
}

/**
 * Re-run the challenge's own self-test.
 *
 * Used at build time: the accepted value must be accepted and a family of
 * near-miss values must be rejected. A template that fails this never reaches a
 * student.
 */
export function selfTest(options: {
  readonly secret: string
  readonly templateId: string
  readonly difficulty: Difficulty
}): { ok: boolean; detail: string } {
  const template = findTemplate(options.templateId)
  if (template === undefined) return { ok: false, detail: `unknown template ${options.templateId}` }
  const variant = template.variants[options.difficulty]
  if (options.secret.length !== variant.secretLength) {
    return {
      ok: false,
      detail: `secret has ${options.secret.length} bytes, template expects ${variant.secretLength}`,
    }
  }
  if (!variant.accepts(options.secret, options.secret)) {
    return { ok: false, detail: 'the accepted value does not satisfy its own predicate' }
  }

  const prefix = options.secret.slice(0, -1)
  const suffix = options.secret.slice(1)
  const swapped = options.secret.length > 1
    ? options.secret[1]! + options.secret[0]! + options.secret.slice(2)
    : options.secret
  const upper = options.secret.toUpperCase()
  const negatives: [string, string][] = [
    ['empty', ''],
    ['prefix', prefix],
    ['suffix', suffix],
    ['trailing byte', `${options.secret}x`],
    ['leading byte', `x${options.secret}`],
  ]
  if (swapped !== options.secret) negatives.push(['first two bytes swapped', swapped])
  if (upper !== options.secret) negatives.push(['upper-cased', upper])

  for (const [label, value] of negatives) {
    if (variant.accepts(options.secret, value)) {
      return { ok: false, detail: `predicate wrongly accepts the ${label} near miss` }
    }
  }
  return { ok: true, detail: `accepted value and ${negatives.length} near misses behave correctly` }
}

/** Bounded, leak-free rendering of a verdict for the model. */
export function describeVerdict(verdict: Verdict): string {
  const lines = [
    `correct: ${verdict.correct ? 'true' : 'false'}`,
    `attempts: ${verdict.attempts}`,
    `decision: ${verdict.tier}`,
    `reason: ${verdict.reason}`,
    `accepted length: ${verdict.acceptedLength}`,
    `submitted length: ${verdict.submittedLength}`,
    `note: ${verdict.note}`,
  ]
  return clampText(lines.join('\n'), 1_200)
}
