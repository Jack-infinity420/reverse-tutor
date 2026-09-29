/**
 * `reverse-tutor` command line: host-side operations that must not be model tools.
 *
 * The tools the agent calls are deliberately narrow. This CLI covers the things an
 * operator needs and a model must not have:
 *
 * - where artefacts and the private verifier store actually live,
 * - what the compiler/runtime situation is on this host,
 * - running the build self-test across every template and difficulty,
 * - writing the IDA bridge target file so the student never pastes a long path,
 * - and answering a challenge from the shell (solving it is the student's job, but
 *   an operator verifying a delivery needs a way to check the pipeline end to end).
 *
 * `verify` prints the verdict only; `show-secret` exists because an operator
 * delivering a lab sometimes has to confirm the generated value, and it is
 * explicitly not part of the model-facing surface.
 *
 * @module dsh-reverse-tutor/cli
 */

import { existsSync, readFileSync, readdirSync } from 'node:fs'
import { join } from 'node:path'
import { DEFAULT_LIMITS, DEFAULT_TUTOR_ROOT, dshHome, publicRoot, tutorRoot, vaultRoot } from './policy.js'
import { TEMPLATES, findTemplate, generateSecret, renderSource } from './challenge/templates.js'
import type { Difficulty } from './challenge/templates.js'
import { buildChallenge } from './challenge/build.js'
import { detectRuntime, detectToolchain, resetToolchainCache } from './challenge/toolchain.js'
import {
  challengePaths,
  readVaultEntry,
  removeChallenge,
  safeSessionId,
  writeBridgeConfig,
  writeVaultEntry,
  answerFingerprint,
} from './challenge/workspace.js'
import { normalizeCandidate, selfTest, verifySubmission } from './verifier.js'
import { describeState, loadState, resetState } from './state.js'
import { parseElf, renderFileView } from './inspect/elf.js'
import { listFunctions, renderObjdump } from './inspect/objdump.js'

const USAGE = `reverse-tutor — DeepSeek Harness Reverse Tutor (IDA Pro edition), host CLI

Usage: reverse-tutor <command> [options]

Commands:
  info                     Show artefact roots, toolchain and runtime detection.
  templates                List templates, difficulties and learning objectives.
  selftest [--keep]        Build every template/difficulty pair and run its self-test.
  build <template> <diff>  Build exactly one challenge and print its id.
                           [--timeout-ms N] overrides the per-attempt compile ceiling.
  render <template> <diff>  Print the injected C source for a fresh secret (no build).
  bridge <challengeId>     Write the IDA bridge target file and print the steps.
  list                     List challenge ids present on disk.
  show <challengeId>       Show the public view of one challenge.
  inspect <challengeId>    Print the file view and analysis anchors.
  disasm <challengeId> [fn] Print disassembly for one function.
  verify <challengeId> <candidate>
                           Run the deterministic verifier and print the verdict.
  show-secret <challengeId> Print the accepted value (operator only).
  state [sessionId]        Print the learning state for a session.
  reset [sessionId]        Clear the learning state for a session.
  remove <challengeId>     Delete a challenge and its verifier record.
  help                     This text.

Environment:
  DSH_HOME                    Harness home (default: ~/.dsh)
  DSH_REVERSE_TUTOR_ROOT      Artefact root (default: ${DEFAULT_TUTOR_ROOT})
  DSH_REVERSE_TUTOR_CC        Explicit compiler path
  DSH_REVERSE_TUTOR_RUNNER    Explicit runtime: "wsl", a qemu path, or "none"
  DSH_REVERSE_TUTOR_TMP       ASCII-only scratch directory for the toolchain
  DSH_REVERSE_TUTOR_ALLOW_EMITTER
                              Set to 1 to accept the compiler-free emitter when no
                              compiler works. Off by default: a failed compile fails
                              the build instead of shipping an artefact with no code
                              structure to analyse.
  DSH_REVERSE_TUTOR_IDA_SCRIPT  Path reported to students for the IDAPython bridge
  DSH_HARNESS_ROOT            Harness checkout, for the schema-conformance test
`

function out(text: string): void {
  process.stdout.write(`${text}\n`)
}

function fail(text: string): number {
  process.stderr.write(`${text}\n`)
  return 1
}

/** `info`: everything an operator needs to judge whether this host can build. */
function commandInfo(): number {
  resetToolchainCache()
  const toolchain = detectToolchain()
  const runtime = detectRuntime()
  out(`DSH home:            ${dshHome()}`)
  out(`artefact root:       ${tutorRoot()}`)
  out(`public challenges:   ${publicRoot()}`)
  out(`verifier vault:      ${vaultRoot()}`)
  out('')
  out(`compiler:            ${toolchain === undefined ? 'NONE FOUND — the deterministic ELF emitter will be used' : `${toolchain.label} (${toolchain.kind})`}`)
  out(`runtime (for verify): ${runtime === undefined ? 'NONE FOUND — verification will use the template predicate' : `${runtime.label} (${runtime.kind})`}`)
  out(`scratch directory:   ${process.env['DSH_REVERSE_TUTOR_TMP'] ?? join(tutorRoot(), 'tmp')}`)
  out('')
  out(`limits: output=${DEFAULT_LIMITS.maxOutputChars} chars, compile=${DEFAULT_LIMITS.compileTimeoutMs}ms, ` +
    `inspect=${DEFAULT_LIMITS.inspectTimeoutMs}ms, submit=${DEFAULT_LIMITS.submitTimeoutMs}ms`)
  return 0
}

function commandTemplates(): number {
  for (const template of TEMPLATES) {
    out(`${template.id}  (topic: ${template.topic})`)
    out(`  teaching: ${template.teaching}`)
    out(`  objectives: ${template.objectives.join(', ')}`)
    out(`  skills: ${template.skills.join(', ')}`)
    for (const difficulty of ['beginner', 'intermediate'] as Difficulty[]) {
      const variant = template.variants[difficulty]
      out(
        `  ${difficulty.padEnd(13)} ${String(variant.secretLength).padStart(2, ' ')} bytes  ` +
          `${variant.emittable ? 'compiler-free emitter: yes' : 'compiler-free emitter: needs a compiler'}  — ${variant.summary}`,
      )
    }
    out('')
  }
  return 0
}

/** `selftest`: build and self-test every variant, with no student involved. */
async function commandSelftest(keep: boolean): Promise<number> {
  let failures = 0
  for (const template of TEMPLATES) {
    for (const difficulty of ['beginner', 'intermediate'] as Difficulty[]) {
      const outcome = await buildChallenge(
        { templateId: template.id, difficulty, sessionId: 'selftest' },
        { compileTimeoutMs: DEFAULT_LIMITS.compileTimeoutMs },
      )
      if (!outcome.ok || outcome.view === undefined) {
        failures += 1
        out(`FAIL  ${template.id}/${difficulty}: ${outcome.message}`)
        for (const warning of outcome.warnings) out(`      warning: ${warning}`)
        continue
      }
      const entry = readVaultEntry(outcome.view.challengeId)
      const test = entry === undefined
        ? { ok: false, detail: 'verifier record missing' }
        : selfTest({ secret: entry.secret, templateId: entry.templateId, difficulty: entry.difficulty })
      const binaryOk = existsSync(outcome.view.binaryPath)
      const magic = binaryOk ? readMagic(outcome.view.binaryPath) : ''
      const elfOk = magic.startsWith('7f 45 4c 46')
      if (!test.ok || !elfOk) failures += 1
      out(
        `${test.ok && elfOk ? 'ok  ' : 'FAIL'}  ${template.id}/${difficulty}  ` +
          `${outcome.view.buildMode}  ${outcome.view.binaryPath}`,
      )
      out(`      magic: ${magic} (${elfOk ? 'ELF' : 'NOT ELF'})  self-test: ${test.detail}`)
      out(`      accepted length: ${outcome.view.acceptedLength} bytes`)
      for (const warning of outcome.warnings) out(`      warning: ${warning}`)
      // `--keep` is what makes this command usable as a demo: without it the
      // challenge is removed as soon as it has been proved buildable, so there is
      // nothing left for the student to open in IDA.
      if (!keep) removeChallenge(outcome.view.challengeId)
    }
  }
  out('')
  out(
    failures === 0
      ? `selftest: all template variants built, parsed as ELF, and passed their self-test${keep ? ' (kept on disk)' : ''}`
      : `selftest: ${failures} failure(s)`,
  )
  return failures === 0 ? 0 : 1
}

function readMagic(path: string): string {
  const bytes = readFileSync(path).subarray(0, 8)
  return [...bytes].map(byte => byte.toString(16).padStart(2, '0')).join(' ')
}

/** `render`: show what a fresh secret produces without building anything. */
function commandRender(templateId: string, difficulty: string): number {
  const template = findTemplate(templateId)
  if (template === undefined) return fail(`unknown template "${templateId}"; try: ${TEMPLATES.map(t => t.id).join(', ')}`)
  const level: Difficulty = difficulty === 'intermediate' ? 'intermediate' : 'beginner'
  const secret = generateSecret(template.variants[level])
  out(`# template=${template.id} difficulty=${level} acceptedLength=${secret.length}`)
  out(`# accepted fingerprint: ${answerFingerprint(secret)}`)
  out(renderSource(template, level, secret))
  return 0
}

/** `build`: create exactly one challenge and print its id. Used by the demo script. */
async function commandBuild(templateId: string, difficulty: string, timeoutOverride?: number): Promise<number> {
  const template = findTemplate(templateId)
  if (template === undefined) return fail(`unknown template "${templateId}"; try: ${TEMPLATES.map(t => t.id).join(', ')}`)
  const level: Difficulty = difficulty.trim().toLowerCase() === 'intermediate' ? 'intermediate' : 'beginner'
  const outcome = await buildChallenge(
    { templateId: template.id, difficulty: level, sessionId: 'cli' },
    { compileTimeoutMs: timeoutOverride ?? DEFAULT_LIMITS.compileTimeoutMs },
  )
  for (const warning of outcome.warnings) out(`warning: ${warning}`)
  if (!outcome.ok || outcome.view === undefined) return fail(outcome.message)
  out(`${outcome.view.challengeId}  ${outcome.view.buildMode}  ${outcome.view.buildSize} bytes`)
  out(`      ${outcome.view.binaryPath}`)
  return 0
}

/** `bridge`: write the target file the IDAPython script reads. */
function commandBridge(challengeId: string): number {
  const entry = readVaultEntry(challengeId)
  if (entry === undefined) return fail(`unknown challenge "${challengeId}"`)
  const paths = challengePaths(challengeId)
  const config = writeBridgeConfig(challengeId)
  const script = process.env['DSH_REVERSE_TUTOR_IDA_SCRIPT'] ?? '(package ida/reverse_tutor_export.py)'
  out(`binary:  ${paths.binaryPath}`)
  out(`context: ${paths.contextPath}`)
  out(`config:  ${config}`)
  out('')
  out('In IDA Pro:')
  out('  1. File > Open, choose the binary above, accept the defaults.')
  out(`  2. Put the cursor inside the function you want to discuss.`)
  out(`  3. Run the export script: ${script}`)
  out(`     (IDA Python console: exec(open(r"${script}").read()))`)
  out('')
  return 0
}

function commandList(): number {
  const root = publicRoot()
  if (!existsSync(root)) {
    out('(no challenges yet)')
    return 0
  }
  const ids = readdirSync(root, { withFileTypes: true }).filter(entry => entry.isDirectory()).map(entry => entry.name)
  if (ids.length === 0) {
    out('(no challenges yet)')
    return 0
  }
  for (const id of ids) {
    const entry = readVaultEntry(id)
    out(
      `${id}  ${entry === undefined ? 'MISSING VERIFIER RECORD' : `${entry.templateId}/${entry.difficulty} len=${entry.answerLength} ${entry.build.mode}`}`,
    )
  }
  return 0
}

function commandShow(challengeId: string): number {
  const entry = readVaultEntry(challengeId)
  if (entry === undefined) return fail(`unknown challenge "${challengeId}"`)
  const paths = challengePaths(challengeId)
  out(`challengeId:      ${entry.challengeId}`)
  out(`template:         ${entry.templateId} (${entry.topic}) at ${entry.difficulty}`)
  out(`created:          ${entry.createdAt}`)
  out(`accepted length:  ${entry.answerLength}`)
  out(`fingerprint:      ${entry.answerFingerprint}`)
  out(`build:            ${entry.build.mode} via ${entry.build.compiler}, ${entry.build.size} bytes`)
  out(`binary:           ${paths.binaryPath}`)
  out(`source:           ${paths.sourcePath}`)
  out(`analysis dir:     ${paths.analysisDir}`)
  return 0
}

function commandInspect(challengeId: string): number {
  const paths = challengePaths(challengeId)
  if (!existsSync(paths.binaryPath)) return fail(`no binary for "${challengeId}"`)
  const info = parseElf(paths.binaryPath)
  out(renderFileView(info))
  out('')
  out('analysis anchors:')
  for (const entry of listFunctions(info)) {
    out(`  ${entry.name} @ 0x${entry.address.toString(16)}${entry.size > 0 ? ` (${entry.size} bytes)` : ''}`)
  }
  return 0
}

function commandDisasm(challengeId: string, selector: string | undefined): number {
  const paths = challengePaths(challengeId)
  if (!existsSync(paths.binaryPath)) return fail(`no binary for "${challengeId}"`)
  const info = parseElf(paths.binaryPath)
  const rendered = renderObjdump(info, selector, { maxInstructions: 200 })
  out(rendered.text)
  return 0
}

async function commandVerify(challengeId: string, candidate: string | undefined): Promise<number> {
  const entry = readVaultEntry(challengeId)
  if (entry === undefined) return fail(`unknown challenge "${challengeId}"`)
  const paths = challengePaths(challengeId)
  const value = candidate ?? ''
  const normalized = normalizeCandidate(value)
  const verdict = await verifySubmission({
    entry,
    binaryPath: paths.binaryPath,
    candidate: value,
    attempts: 1,
    timeoutMs: DEFAULT_LIMITS.submitTimeoutMs,
  })
  out(`correct:  ${verdict.correct}`)
  out(`decision: ${verdict.tier}`)
  out(`reason:   ${verdict.reason}`)
  out(`length:   submitted=${verdict.submittedLength} accepted=${verdict.acceptedLength}`)
  out(`note:     ${verdict.note}`)
  if (normalized.changed) out(`normalised: ${normalized.notes.join('; ')}`)
  return verdict.correct ? 0 : 2
}

function commandShowSecret(challengeId: string): number {
  const entry = readVaultEntry(challengeId)
  if (entry === undefined) return fail(`unknown challenge "${challengeId}"`)
  out(entry.secret)
  return 0
}

function commandState(sessionId: string): number {
  out(describeState(loadState(safeSessionId(sessionId)), 4_000))
  return 0
}

function commandReset(sessionId: string): number {
  resetState(safeSessionId(sessionId))
  out(`cleared learning state for session ${safeSessionId(sessionId)}`)
  return 0
}

function commandRemove(challengeId: string): number {
  if (readVaultEntry(challengeId) === undefined && !existsSync(challengePaths(challengeId).publicDir)) {
    return fail(`unknown challenge "${challengeId}"`)
  }
  removeChallenge(challengeId)
  out(`removed ${challengeId}`)
  return 0
}

/** Entry point. */
export async function main(argv: readonly string[]): Promise<number> {
  const [command, ...rest] = argv
  switch (command) {
    case undefined:
    case 'help':
    case '--help':
    case '-h':
      out(USAGE.trimEnd())
      return 0
    case 'info':
      return commandInfo()
    case 'templates':
      return commandTemplates()
    case 'selftest':
      return commandSelftest(rest.includes('--keep'))
    case 'build': {
      const words = rest.filter(value => !value.startsWith('--'))
      const timeoutFlag = rest.findIndex(value => value === '--timeout-ms')
      const parsed = timeoutFlag === -1 ? undefined : Number(rest[timeoutFlag + 1])
      const override = parsed !== undefined && Number.isFinite(parsed) && parsed > 0 ? parsed : undefined
      return commandBuild(words[0] ?? 'xor-loop', words[1] ?? 'beginner', override)
    }
    case 'render':
      return commandRender(rest[0] ?? 'xor-loop', rest[1] ?? 'beginner')
    case 'bridge':
      return rest[0] === undefined ? fail('bridge needs a challengeId') : commandBridge(rest[0])
    case 'list':
      return commandList()
    case 'show':
      return rest[0] === undefined ? fail('show needs a challengeId') : commandShow(rest[0])
    case 'inspect':
      return rest[0] === undefined ? fail('inspect needs a challengeId') : commandInspect(rest[0])
    case 'disasm':
      return rest[0] === undefined ? fail('disasm needs a challengeId') : commandDisasm(rest[0], rest[1])
    case 'verify':
      return rest[0] === undefined ? fail('verify needs a challengeId') : commandVerify(rest[0], rest[1])
    case 'show-secret':
      return rest[0] === undefined ? fail('show-secret needs a challengeId') : commandShowSecret(rest[0])
    case 'state':
      return commandState(rest[0] ?? 'cli')
    case 'reset':
      return commandReset(rest[0] ?? 'cli')
    case 'remove':
      return rest[0] === undefined ? fail('remove needs a challengeId') : commandRemove(rest[0])
    default:
      return fail(`unknown command "${command}"\n\n${USAGE.trimEnd()}`)
  }
}

/** Persist a verifier record; exported for tests and for an external orchestrator. */
export function persistEntry(entry: Parameters<typeof writeVaultEntry>[0]): void {
  writeVaultEntry(entry)
}

// Run when invoked as a program rather than imported by a test.
const invokedDirectly = ((): boolean => {
  const entry = process.argv[1]
  if (entry === undefined) return false
  return /cli\.(js|ts)$/.test(entry.replace(/\\/g, '/'))
})()

if (invokedDirectly) {
  main(process.argv.slice(2))
    .then(code => {
      process.exitCode = code
    })
    .catch((error: unknown) => {
      process.stderr.write(`${error instanceof Error ? (error.stack ?? error.message) : String(error)}\n`)
      process.exitCode = 1
    })
}
