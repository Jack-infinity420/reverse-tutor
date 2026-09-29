/**
 * Challenge workspaces, the private verifier vault, and the IDA bridge handoff.
 *
 * Two directories are created per challenge and they are deliberately separate:
 *
 * - **public** (`<root>/challenges/<id>/`) — the ELF, the injected C source, a
 *   brief, and an empty `analysis/` directory. Both the student and the agent
 *   may read everything here.
 * - **vault** (`<root>/vault/<id>/`) — the accepted value, the canonical
 *   fingerprint, and the build record. No tool in this plugin exposes a vault
 *   path or its contents, and it lives outside the session workspace so the
 *   agent's own file tools cannot reach it by accident.
 *
 * @module dsh-reverse-tutor/challenge/workspace
 */

import { createHash } from 'node:crypto'
import { existsSync, mkdirSync, readFileSync, rmSync } from 'node:fs'
import { join } from 'node:path'
import {
  assertSafeSegment,
  ensureDir,
  publicRoot,
  readJson,
  resolveInside,
  tutorRoot,
  vaultRoot,
  writeFileAtomic,
  writeJsonAtomic,
} from '../policy.js'
import type { Difficulty } from './templates.js'
import { findTemplate } from './templates.js'

/** Build provenance recorded in the vault. */
export interface BuildRecord {
  /** Compiler used, or `none` for the deterministic fallback builder. */
  readonly compiler: string
  /** Compiler arguments, verbatim. */
  readonly args: readonly string[]
  /** `built` when a real ELF was produced, `fallback` when the ELF writer ran. */
  readonly mode: 'built' | 'fallback'
  /** Size of the produced binary, in bytes. */
  readonly size: number
  /** SHA-256 of the produced binary. */
  readonly sha256: string
  /** Populated when a real compile was attempted and failed. */
  readonly error?: string
}

/** Verifier-owned record for one challenge; never returned to the model. */
export interface VaultEntry {
  readonly challengeId: string
  readonly sessionId: string
  readonly templateId: string
  readonly topic: string
  readonly difficulty: Difficulty
  /** The accepted value. Held only here. */
  readonly secret: string
  /** Salted digest, safe to log and to compare across rebuilds. */
  readonly answerFingerprint: string
  readonly answerLength: number
  readonly createdAt: string
  readonly build: BuildRecord
}

/** Public challenge identity handed to the model. */
export interface ChallengeView {
  readonly challengeId: string
  readonly templateId: string
  readonly topic: string
  readonly difficulty: Difficulty
  readonly teaching: string
  readonly objectives: readonly string[]
  readonly publicDir: string
  readonly binaryPath: string
  readonly sourcePath: string
  readonly analysisDir: string
  readonly acceptedLength: number
  readonly buildMode: 'built' | 'fallback'
  readonly compiler: string
  /** Size of the delivered binary, in bytes. */
  readonly buildSize: number
}

/** Everything one challenge occupies on disk. */
export interface ChallengePaths {
  readonly publicDir: string
  readonly vaultDir: string
  readonly binaryPath: string
  readonly sourcePath: string
  readonly analysisDir: string
  readonly contextPath: string
  readonly bridgeConfigPath: string
}

/** Normalise a session id into a safe directory name. */
export function safeSessionId(sessionId: string | undefined): string {
  const raw = (sessionId ?? 'session').trim()
  const cleaned = raw.replace(/[^A-Za-z0-9._-]/g, '-').replace(/^[^A-Za-z0-9]+/, '')
  return cleaned.length === 0 ? 'session' : cleaned.slice(0, 96)
}

/** Validate a challenge id supplied by the model. */
export function requireChallengeId(challengeId: string): string {
  return assertSafeSegment(challengeId, 'challengeId')
}

/**
 * Build a challenge id — which is also the folder name — from the topic.
 *
 * The student's own words become the directory: "构造函数与析构函数逆向分析"
 * becomes `构造函数与析构函数逆向分析challenge`. Every build gets a FRESH
 * folder: when the plain name is already taken — in the public root or in the
 * vault — a numeric suffix is appended (`…challenge-2`, `…challenge-3`), so
 * new artefacts never land in an older challenge's directory.
 */
export function newChallengeId(templateId: string, topic?: string): string {
  const stem = `${topicFolderBase(topic) ?? templateId}challenge`
  let candidate = stem
  for (let suffix = 2; suffix <= 999; suffix++) {
    if (!existsSync(join(publicRoot(), candidate)) && !existsSync(join(vaultRoot(), candidate))) {
      return candidate
    }
    candidate = `${stem}-${suffix}`
  }
  throw new Error(`could not allocate a fresh challenge folder for topic: ${topic ?? templateId}`)
}

/**
 * Turn a free-form topic into a folder-name fragment: strip the characters
 * Windows forbids in file names, fold whitespace runs into dashes, collapse
 * dot runs so no parent reference can survive, and cap the length so the
 * folder stays usable under long base paths.
 */
function topicFolderBase(topic: string | undefined): string | undefined {
  if (topic === undefined) return undefined
  const cleaned = topic
    .replace(/[<>:"|?*/\\\x00-\x1f]/g, '')
    .replace(/\s+/g, '-')
    .replace(/\.{2,}/g, '.')
    .replace(/^[-.\s]+|[-.\s]+$/g, '')
  const capped = [...cleaned].slice(0, 60).join('')
  return capped === '' ? undefined : capped
}

/** Resolve every path for one challenge, proving each stays inside its root. */
export function challengePaths(challengeId: string): ChallengePaths {
  const id = requireChallengeId(challengeId)
  const publicDir = resolveInside(publicRoot(), id)
  const vaultDir = resolveInside(vaultRoot(), id)
  return {
    publicDir,
    vaultDir,
    binaryPath: resolveInside(publicDir, 'challenge'),
    sourcePath: resolveInside(publicDir, 'challenge.c'),
    analysisDir: resolveInside(publicDir, 'analysis'),
    contextPath: resolveInside(publicDir, 'ida_context.json'),
    bridgeConfigPath: resolveInside(publicDir, 'rt_bridge.json'),
  }
}

/** Salted fingerprint of an accepted value: comparable, not reversible. */
export function answerFingerprint(secret: string): string {
  const pepper = 'reverse-tutor/v1'
  return createHash('sha256').update(`${pepper}:${secret}`).digest('hex').slice(0, 32)
}

/** Hash a file, or `undefined` when it is missing. */
export function fileSha256(path: string): string | undefined {
  if (!existsSync(path)) return undefined
  return createHash('sha256').update(readFileSync(path)).digest('hex')
}

/** Create the public and vault directory trees for a challenge. */
export function createWorkspace(challengeId: string): ChallengePaths {
  const paths = challengePaths(challengeId)
  ensureDir(paths.publicDir)
  ensureDir(paths.analysisDir)
  ensureDir(paths.vaultDir)
  const privateDir = resolveInside(paths.vaultDir, 'private')
  ensureDir(privateDir)
  return paths
}

/** Persist the verifier record. */
export function writeVaultEntry(entry: VaultEntry): void {
  const paths = challengePaths(entry.challengeId)
  ensureDir(paths.vaultDir)
  writeJsonAtomic(resolveInside(paths.vaultDir, 'verifier.json'), entry)
}

/** Load the verifier record, or `undefined` when the challenge does not exist. */
export function readVaultEntry(challengeId: string): VaultEntry | undefined {
  const paths = challengePaths(challengeId)
  const raw = readJson<VaultEntry>(resolveInside(paths.vaultDir, 'verifier.json'))
  if (raw === undefined) return undefined
  if (typeof raw.secret !== 'string' || raw.secret.length === 0) return undefined
  if (findTemplate(raw.templateId) === undefined) return undefined
  return raw
}

/** Public view of a challenge, derived from the vault record. */
export function challengeView(entry: VaultEntry): ChallengeView {
  const paths = challengePaths(entry.challengeId)
  const template = findTemplate(entry.templateId)
  return {
    challengeId: entry.challengeId,
    templateId: entry.templateId,
    topic: entry.topic,
    difficulty: entry.difficulty,
    teaching: template?.teaching ?? entry.topic,
    objectives: template?.objectives ?? [],
    publicDir: paths.publicDir,
    binaryPath: paths.binaryPath,
    sourcePath: paths.sourcePath,
    analysisDir: paths.analysisDir,
    acceptedLength: entry.answerLength,
    buildMode: entry.build.mode,
    compiler: entry.build.compiler,
    buildSize: entry.build.size,
  }
}

/**
 * Write the per-challenge bridge descriptor.
 *
 * The IDAPython export script reads this file so the student never has to paste
 * a long absolute path into IDA's console. It contains only the output path,
 * the challenge id, and a reminder — never the accepted value.
 */
export function writeBridgeConfig(challengeId: string): string {
  const paths = challengePaths(challengeId)
  const payload = {
    schema: 'reverse-tutor/bridge/v1',
    challengeId,
    outputPath: paths.contextPath,
    hint: 'Run the Reverse Tutor export script while this challenge is open in IDA Pro.',
  }
  writeJsonAtomic(paths.bridgeConfigPath, payload)
  return paths.bridgeConfigPath
}

/** Read the bridge descriptor, when the challenge has one. */
export function readBridgeConfig(challengeId: string): { outputPath?: string } | undefined {
  const paths = challengePaths(challengeId)
  return readJson<{ outputPath?: string }>(paths.bridgeConfigPath)
}

/** Create `README.md` and `analysis/README.md` for the student. */
export function writeStudentDocs(view: ChallengeView, secretLengthKnown: boolean): void {
  const paths = challengePaths(view.challengeId)
  const brief = [
    `# Challenge ${view.challengeId}`,
    '',
    `| field | value |`,
    `|---|---|`,
    `| topic | \`${view.topic}\` |`,
    `| template | \`${view.templateId}\` |`,
    `| difficulty | \`${view.difficulty}\` |`,
    `| binary | \`challenge\` (ELF32 i386, opens in ida.exe) |`,
    `| analysis notes | \`analysis/\` |`,
    '',
    '## What to do',
    '',
    '1. Open `challenge` in IDA Pro. Let auto-analysis finish.',
    '2. Work out the accepted value. Do not guess: every conclusion needs an',
    '   address, an instruction, or a data reference behind it.',
    '3. When your tutor asks what you are looking at, run the Reverse Tutor',
    '   export script so your current function reaches the tutor as JSON.',
    '4. Submit the accepted value to the tutor for verification.',
    '',
    '## Learning objectives',
    '',
    ...view.objectives.map(objective => `- \`${objective}\``),
    '',
    '## Verification',
    '',
    'The tutor verifies the accepted value deterministically; the binary itself',
    'exits 0 only for that value, so you can also confirm locally with:',
    '',
    '```bash',
    `# on a Linux host`,
    `printf '%s\\n' '<your candidate>' | ./challenge && echo accepted`,
    '```',
    '',
    secretLengthKnown
      ? `Accepted-value length: **${view.acceptedLength} bytes**. That is a hint about shape, not about content.`
      : '',
    '',
  ].join('\n')
  writeFileAtomic(resolveInside(paths.publicDir, 'README.md'), brief)

  const analysis = [
    '# Analysis notes',
    '',
    'Write your evidence here as you go. Useful shapes:',
    '',
    '- `0x4011a0  movzx eax, byte ptr [rdi+rcx]` — where the input byte is loaded',
    '- `0x4011a4  xor al, 0x37` — the transform applied to it',
    '- `.rodata:0x402000` — the reference data it is compared against',
    '',
    'Keep raw instruction addresses in your notes: they are what makes a claim',
    'checkable.',
    '',
  ].join('\n')
  writeFileAtomic(resolveInside(paths.analysisDir, 'README.md'), analysis)
}

/** Remove a challenge from disk (used by tests and the CLI). */
export function removeChallenge(challengeId: string): void {
  const paths = challengePaths(challengeId)
  rmSync(paths.publicDir, { recursive: true, force: true })
  rmSync(paths.vaultDir, { recursive: true, force: true })
}

/** Absolute path of the IDAPython bridge script shipped with this package. */
export function bridgeScriptPath(packageRoot: string): string {
  return join(packageRoot, 'ida', 'reverse_tutor_export.py')
}

/** The root the plugin owns, exposed for diagnostics. */
export function tutorInfo(): { root: string; publicRoot: string; vaultRoot: string } {
  const root = tutorRoot()
  const info = { root, publicRoot: publicRoot(), vaultRoot: vaultRoot() }
  mkdirSync(info.publicRoot, { recursive: true })
  return info
}
