/**
 * Platform and filesystem safety primitives for the Reverse Tutor plugin.
 *
 * Everything here is deliberately dependency-free: the plugin must load with
 * nothing but Node builtins so a profile install can never fail on a missing
 * transitive package.
 *
 * @module dsh-reverse-tutor/policy
 */

import { existsSync, mkdirSync, readFileSync, renameSync, unlinkSync, writeFileSync } from 'node:fs'
import { homedir } from 'node:os'
import { isAbsolute, join, normalize, parse, resolve, sep } from 'node:path'

/** Hard ceilings applied to every tool surface. */
export interface ReverseTutorLimits {
  /** Maximum characters any single tool result may hand back to the model. */
  readonly maxOutputChars: number
  /** Wall-clock budget for a compiler invocation, in milliseconds. */
  readonly compileTimeoutMs: number
  /** Wall-clock budget for a bundled inspection command, in milliseconds. */
  readonly inspectTimeoutMs: number
  /** Wall-clock budget for a submission, in milliseconds. */
  readonly submitTimeoutMs: number
  /** Maximum accepted size of a caller-supplied challenge source, in characters. */
  readonly maxSourceChars: number
  /** Maximum accepted length of a candidate answer, in characters. */
  readonly maxCandidateChars: number
}

/** Default ceilings, matching the security section of the implementation spec. */
export const DEFAULT_LIMITS: ReverseTutorLimits = {
  maxOutputChars: 12_000,
  compileTimeoutMs: 20_000,
  inspectTimeoutMs: 8_000,
  submitTimeoutMs: 5_000,
  maxSourceChars: 40_000,
  maxCandidateChars: 256,
}

/** Resolve the DSH home directory the same way the harness does. */
export function dshHome(): string {
  const configured = process.env['DSH_HOME']
  if (configured !== undefined && configured.trim() !== '') return resolve(configured)
  return join(homedir(), '.dsh')
}

/**
 * The one writable root this plugin owns.
 *
 * It sits outside the session workspace on purpose: the private verifier store
 * must not be reachable by the agent's own file tools, and a per-session
 * workspace would make a challenge disappear between sessions.
 *
 * The default is a dedicated folder under the user's home directory rather than
 * something under `DSH_HOME`, because the challenges are *student* material:
 * they are meant to be opened in IDA Pro, browsed in Explorer, and kept between
 * sessions, so they belong where the operator can see them rather than in a
 * dot-directory. `DSH_REVERSE_TUTOR_ROOT` overrides it for any other layout.
 */
export const DEFAULT_TUTOR_ROOT = join(homedir(), 'reverse-tutor')

export function tutorRoot(): string {
  const configured = process.env['DSH_REVERSE_TUTOR_ROOT']
  if (configured !== undefined && configured.trim() !== '') return resolve(configured)
  return resolve(DEFAULT_TUTOR_ROOT)
}

/**
 * Where the challenges live, and what the student is told to open.
 *
 * Layout under one challenge id:
 *   `challenge` (the ELF), `challenge.c`, `mini_libc.h`, `README.md`,
 *   `rt_bridge.json`, `ida_context.json`, `analysis/`.
 */
export function publicRoot(): string {
  return join(tutorRoot(), 'challenges')
}

/**
 * Verifier-owned storage: the accepted values, their fingerprints, and the build
 * records. Nothing outside this plugin resolves a path into it.
 */
export function vaultRoot(): string {
  return join(tutorRoot(), 'vault')
}

/** Learning-state location, one file per session workspace id. */
export function stateRoot(): string {
  return join(tutorRoot(), 'state')
}

/** Create a directory tree if it is missing. */
export function ensureDir(path: string): string {
  mkdirSync(path, { recursive: true })
  return path
}

/**
 * Reject anything that is not plainly a single safe path segment.
 *
 * Used for identifiers that become directory names (`challengeId`,
 * `sessionId`), which is the only place a caller-supplied string may influence
 * a path at all. Everything else in this plugin resolves against a root that
 * the plugin itself computed.
 *
 * The segment may carry any printable character — including CJK, so a
 * challenge id can carry the topic's Chinese name — but never a path
 * separator, a parent-directory reference, a NUL, or a character Windows
 * forbids in file names; and it may not end in a dot or a space, which
 * Windows would silently strip, pointing the id at a different directory than
 * the one that was validated. Containment under the configured root is
 * enforced separately by `resolveInside`.
 */
export function assertSafeSegment(value: string, label: string): string {
  if (typeof value !== 'string' || value.length === 0) {
    throw new Error(`${label} must be a non-empty string`)
  }
  if (value.length > 128) throw new Error(`${label} is too long`)
  if (value === '.' || value === '..' || value.includes('..') || value.includes('/') || value.includes('\\')) {
    throw new Error(`${label} may not contain path separators or parent-directory references`)
  }
  // eslint-disable-next-line no-control-regex
  if (/[<>:"|?*\x00-\x1f]/.test(value)) {
    throw new Error(`${label} contains a character that is illegal in a file name`)
  }
  if (value.endsWith('.') || value.endsWith(' ')) {
    throw new Error(`${label} may not end with a dot or a space`)
  }
  return value
}

/**
 * Resolve `candidate` under `root` and prove the result cannot escape it.
 *
 * This is the single path-containment gate: every filesystem operation that
 * accepts a caller-supplied name goes through it, so `../../../etc/passwd`,
 * an absolute path, or a Windows drive-relative path all fail here rather than
 * at the filesystem.
 */
export function resolveInside(root: string, candidate: string): string {
  if (typeof candidate !== 'string' || candidate.length === 0) {
    throw new Error('path must be a non-empty string')
  }
  if (candidate.includes('\0')) throw new Error('path may not contain NUL')
  const base = resolve(root)
  const target = isAbsolute(candidate) ? normalize(candidate) : resolve(base, candidate)
  const rootWithSep = base.endsWith(sep) ? base : base + sep
  if (target !== base && !target.startsWith(rootWithSep)) {
    throw new Error(`path escapes its allowed root: ${candidate}`)
  }
  return target
}

/** Atomically replace a text file (write sibling temp, then rename). */
export function writeFileAtomic(path: string, contents: string): void {
  const temp = `${path}.${process.pid}.tmp`
  writeFileSync(temp, contents, { encoding: 'utf8' })
  try {
    renameSync(temp, path)
  } catch (error) {
    try {
      unlinkSync(path)
      renameSync(temp, path)
    } catch {
      try {
        unlinkSync(temp)
      } catch {
        /* best effort */
      }
      throw error
    }
  }
}

/** Read JSON, or return `undefined` when the file is absent or unparseable. */
export function readJson<T>(path: string): T | undefined {
  if (!existsSync(path)) return undefined
  try {
    return JSON.parse(readFileSync(path, 'utf8')) as T
  } catch {
    return undefined
  }
}

/** Write JSON with a stable two-space layout. */
export function writeJsonAtomic(path: string, value: unknown): void {
  writeFileAtomic(path, `${JSON.stringify(value, null, 2)}\n`)
}

/** Truncate a payload to the configured character budget with an explicit notice. */
export function clampText(text: string, maxChars: number, note = 'output truncated'): string {
  if (text.length <= maxChars) return text
  const head = text.slice(0, Math.max(0, maxChars - 120))
  return `${head}\n\n[... ${note}: ${text.length - head.length} more characters omitted ...]`
}

/** Keep only basenames of the toolchain path when reporting to the model. */
export function shortPath(path: string): string {
  const parsed = parse(path)
  return parsed.base === '' ? path : parsed.base
}

/** Monotonic-ish identifier suffix for challenge ids. */
export function stamp(date = new Date()): string {
  const pad = (value: number, width = 2): string => String(value).padStart(width, '0')
  return (
    `${date.getFullYear()}${pad(date.getMonth() + 1)}${pad(date.getDate())}` +
    `-${pad(date.getHours())}${pad(date.getMinutes())}${pad(date.getSeconds())}`
  )
}
