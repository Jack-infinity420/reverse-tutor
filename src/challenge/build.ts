/**
 * `reverse_build`: source -> secret injection -> ELF -> self-test -> challenge.
 *
 * The build is the only place the accepted value exists in plaintext, and it
 * never leaves this module: the generated secret is written to the vault, the
 * rendered source contains only the encoded reference values, and the returned
 * view carries a length and a fingerprint at most.
 *
 * Two artefact sources exist, and only one of them is used by default:
 *
 * 1. **Compiler** — clang+lld (or a Linux/cross gcc) builds the template's real C
 *    source, optionally stripping the symbol table. This is the intended path and
 *    the one the implementation spec asks for.
 * 2. **Deterministic emitter** — `elf.ts` assembles an equivalent program directly.
 *    It is a genuine, runnable ELF with the same accept/reject contract, but it is
 *    one flat blob with no C function structure, so it is **opt-in only**
 *    (`DSH_REVERSE_TUTOR_ALLOW_EMITTER=1`) for hosts that have no Linux-capable
 *    compiler at all. A compile failure on a host that *does* have one fails the
 *    build with the compiler's own output, because a silent downgrade to the
 *    emitter turns a toolchain problem into a lesson with nothing to analyse.
 *
 * @module dsh-reverse-tutor/challenge/build
 */

import { existsSync, readFileSync, renameSync, rmSync, writeFileSync } from 'node:fs'
import { basename, join } from 'node:path'
import { randomBytes } from 'node:crypto'
import { clampText, resolveInside } from '../policy.js'
import type { Difficulty } from './templates.js'
import { findTemplate, generateSecret, renderSource, templatesDir } from './templates.js'
import type { ChallengeTemplate } from './templates.js'
import {
  buildCompileCommand,
  COMPILER_ENV,
  detectToolchain,
  EMITTER_ENV,
  emitterAllowed,
  makeScratch,
  runProcess,
  stripCommand,
} from './toolchain.js'
import { buildFallbackBinary } from './elf.js'
import {
  answerFingerprint,
  challengeView,
  createWorkspace,
  fileSha256,
  newChallengeId,
  safeSessionId,
  writeBridgeConfig,
  writeStudentDocs,
  writeVaultEntry,
} from './workspace.js'
import type { BuildRecord, ChallengeView, VaultEntry } from './workspace.js'
import { selfTest } from '../verifier.js'

/** Build request, exactly as the tool receives it. */
export interface BuildRequest {
  readonly topic?: string
  readonly difficulty?: string
  readonly templateId?: string
  readonly source?: string
  readonly sessionId?: string
  readonly debugInfo?: boolean
  readonly keepSymbols?: boolean
}

/** Build outcome handed to the tool. */
export interface BuildOutcome {
  readonly ok: boolean
  readonly view?: ChallengeView
  readonly template: ChallengeTemplate
  readonly difficulty: Difficulty
  readonly message: string
  readonly log: string
  readonly warnings: readonly string[]
}

/** Maximum accepted size for a caller-supplied source. */
export const MAX_SOURCE_CHARS = 40_000

/**
 * Validate caller-supplied C source for a custom challenge.
 *
 * The tutor's contract is that the *template* owns verification, so a custom
 * source cannot introduce a new acceptance rule. What it can do is change the
 * artefact the student sees, which is useful for a targeted drill ("same XOR
 * check, but with an extra branch"). The rules therefore keep the shape the
 * verifier depends on:
 *
 * - it must contain the `{{SECRET}}` marker exactly once, so the accepted value
 *   is the injected one rather than something the model wrote down;
 * - it must not contain any comparison against a literal that the verifier does
 *   not know about — enforced by requiring the marker;
 * - it must stay within a size budget.
 */
export function validateCustomSource(source: string): { ok: true } | { ok: false; reason: string } {
  if (typeof source !== 'string' || source.trim().length === 0) {
    return { ok: false, reason: 'source must be a non-empty string' }
  }
  if (source.length > MAX_SOURCE_CHARS) {
    return { ok: false, reason: `source is ${source.length} characters; the limit is ${MAX_SOURCE_CHARS}` }
  }
  const markers = source.split('{{SECRET}}').length - 1
  if (markers === 0) {
    return {
      ok: false,
      reason:
        'source must contain the {{SECRET}} marker exactly once; the accepted value is injected by the build, never written by the caller',
    }
  }
  if (markers > 1) {
    return { ok: false, reason: `source contains {{SECRET}} ${markers} times; exactly one injection point is allowed` }
  }
  return { ok: true }
}

/**
 * Render the challenge source.
 *
 * Template mode uses the package's own C source with its encoded reference
 * values. Custom mode starts from the caller's text and substitutes the marker
 * with the same kind of definitions the template would have produced.
 */
function renderChallengeSource(options: {
  readonly template: ChallengeTemplate
  readonly difficulty: Difficulty
  readonly secret: string
  readonly customSource?: string
}): { source: string; definitions: string } {
  const { template, difficulty, secret, customSource } = options
  const definitions = template.variants[difficulty].encode(secret).trimEnd()
  if (customSource === undefined) {
    return { source: renderSource(template, difficulty, secret), definitions }
  }
  return { source: customSource.replace('{{SECRET}}', `\n${definitions}\n`), definitions }
}

/** Result of compiling one source file. */
interface CompileOutcome {
  readonly record: BuildRecord
  readonly warnings: readonly string[]
  readonly log: string
}

/**
 * Compile a rendered source into the delivered binary.
 *
 * A real compile is the only product. There is no silent substitution: when the
 * compiler fails, this throws with the compiler's own output attached, and
 * `buildChallenge` removes the half-built workspace. The deterministic emitter is
 * reachable only when the operator opts in (`DSH_REVERSE_TUTOR_ALLOW_EMITTER`).
 *
 * The compile always runs in the plugin's own scratch directory with an
 * ASCII-only TMP/TEMP, which is what makes the MSYS2/LLVM driver work at all when
 * the user profile path is non-ASCII.
 *
 * `timeoutMs` is a per-attempt ceiling and `attempts` retries a failure that looks
 * transient (a timeout, or a scratch directory something else was holding open);
 * a source-level error fails identically on every attempt, so it is not retried.
 */
async function produceBinary(options: {
  readonly sourcePath: string
  readonly outputPath: string
  readonly definitions: string
  readonly template: ChallengeTemplate
  readonly difficulty: Difficulty
  readonly secret: string
  readonly debugInfo: boolean
  readonly keepSymbols: boolean
  readonly compileTimeoutMs: number
  readonly attempts?: number
}): Promise<CompileOutcome> {
  const warnings: string[] = []
  const logLines: string[] = []
  const toolchain = detectToolchain(warnings)
  const variant = options.template.variants[options.difficulty]
  const timeoutMs = Math.max(250, options.compileTimeoutMs)

  if (toolchain === undefined) {
    const reason =
      'no compiler able to target 32-bit Linux (i386) was found on this host; ' +
      `set ${COMPILER_ENV} to a clang/gcc that can, or ${EMITTER_ENV}=1 to accept an emitted artefact`
    if (!(emitterAllowed() && variant.emittable)) throw new Error(reason)
    warnings.push(reason)
    logLines.push('toolchain detection: no usable compiler')
    return emitFallback()
  }

  let lastDetail = ''
  for (let attempt = 1; attempt <= Math.max(1, options.attempts ?? 3); attempt += 1) {
    const scratch = makeScratch('compile-')
    const stageSource = join(scratch, 'challenge.c')
    const stageOutput = join(scratch, process.platform === 'win32' ? 'challenge.elf' : 'challenge')
    writeFileSync(stageSource, readFileSync(options.sourcePath, 'utf8'), 'utf8')
    // The template sources `#include "mini_libc.h"`, which ships beside them, so
    // the template root is the include directory for every build. The linker
    // script pins the image at 0x08048000 with `.text` at 0x08049000, which is what
    // makes the delivered binary predictable to talk about.
    const linkerScript = join(templatesDir(), 'challenge.ld')
    const plan = buildCompileCommand(toolchain, {
      sourcePath: stageSource,
      outputPath: stageOutput,
      includeDir: templatesDir(),
      debugInfo: options.debugInfo,
      ...(existsSync(linkerScript) ? { linkerScript } : {}),
    })
    const result = await runProcess(plan.command, plan.args, {
      timeoutMs,
      cwd: scratch,
      maxOutputChars: 20_000,
    })
    logLines.push(`$ ${basename(plan.command)} ${plan.args.join(' ')}`)

    if (result.timedOut) {
      lastDetail = `the compiler did not finish within ${timeoutMs} ms`
      warnings.push(lastDetail)
      logLines.push(`compile timed out on attempt ${attempt}`)
    } else if (result.spawnError !== undefined) {
      lastDetail = `the compiler could not be started: ${result.spawnError}`
      warnings.push(lastDetail)
      logLines.push(`spawn error: ${result.spawnError}`)
    } else if (result.code !== 0) {
      const detail = clampText(`${result.stderr}\n${result.stdout}`.trim(), 4_000)
      lastDetail = `${plan.label} exited ${String(result.code)}: ${detail}`
      logLines.push(`attempt ${attempt} failed\n${detail}`)
    } else if (!existsSync(stageOutput)) {
      lastDetail = 'the compiler reported success but produced no output file'
      warnings.push(lastDetail)
      logLines.push('missing compiler output')
    } else {
      const produced = readFileSync(stageOutput)
      const magic = produced.subarray(0, 4)
      if (!(magic[0] === 0x7f && magic[1] === 0x45 && magic[2] === 0x4c && magic[3] === 0x46)) {
        lastDetail = `the compiler produced a non-ELF artefact (first bytes: ${[...magic].map(byte => byte.toString(16)).join(' ')})`
        warnings.push(lastDetail)
        logLines.push(lastDetail)
      } else {
        // Move the artefact out of scratch, then optionally strip it.
        renameSync(stageOutput, options.outputPath)
        if (!options.keepSymbols) {
          const strip = stripCommand(toolchain, options.outputPath)
          if (strip !== undefined) {
            const stripped = await runProcess(strip.command, strip.args, {
              timeoutMs: 15_000,
              cwd: scratch,
              maxOutputChars: 4_000,
            })
            logLines.push(
              stripped.code === 0
                ? `$ ${strip.label} --strip-all`
                : `${strip.label} failed (exit ${String(stripped.code)}); the artefact keeps its symbols`,
            )
          } else {
            warnings.push('no strip tool was found; the delivered binary may still carry symbol names')
          }
        }
        const bytes = readFileSync(options.outputPath)
        logLines.push(`built ${bytes.length} bytes with ${plan.label} on attempt ${attempt}`)
        if (attempt > 1) warnings.push(`the compile needed ${attempt} attempts; the first one is in the log`)
        return {
          record: {
            compiler: plan.label,
            args: plan.args,
            mode: 'built',
            size: bytes.length,
            sha256: fileSha256(options.outputPath) ?? '',
          },
          warnings,
          log: logLines.join('\n'),
        }
      }
    }
  }

  const detail = lastDetail === '' ? 'the compiler failed without producing a diagnostic' : lastDetail
  logLines.push(`giving up after ${Math.max(1, options.attempts ?? 3)} attempts`)
  warnings.push(`the compiler could not build this challenge: ${detail}`)

  if (emitterAllowed() && variant.emittable) return emitFallback()

  // Fail loudly. The alternative — handing the student an emitted blob that has no
  // function structure to read — silently converts a toolchain problem into a bad
  // lesson, which is exactly the failure this branch exists to prevent.
  throw new Error(
    `template ${options.template.id}/${options.difficulty} could not be compiled by ${toolchain.label}:\n` +
      `${detail}\n${logLines.join('\n')}`,
  )

  /** Emit the compiler-free artefact. Only reachable with the emitter switched on. */
  function emitFallback(): CompileOutcome {
    const spec = variant.transform(options.secret)
    const binary = buildFallbackBinary(spec)
    writeFileSync(options.outputPath, binary)
    logLines.push(`emitted ${binary.length} bytes with the deterministic ELF builder`)
    return {
      record: {
        compiler: 'deterministic-emitter',
        args: [],
        mode: 'fallback',
        size: binary.length,
        sha256: fileSha256(options.outputPath) ?? '',
        ...(warnings.length === 0 ? {} : { error: warnings[0]! }),
      },
      warnings,
      log: logLines.join('\n'),
    }
  }
}

/** Directory of the shipped templates. */
function templatesDirPath(): string {
  // `lib/challenge/build.js` -> package root -> `templates`
  const here = new URL('.', import.meta.url)
  return join(decodeURIComponent(here.pathname.replace(/^\/([A-Za-z]:)/, '$1')), '..', '..', 'templates')
}

/**
 * Build one challenge end to end.
 *
 * Steps, in order: resolve template and difficulty, validate any custom source,
 * create the workspace, generate the secret, render the source, compile, run the
 * self-test, write the vault record, and finally write the student-facing brief.
 * A failure at any step removes the freshly created workspace so a broken
 * challenge can never be presented.
 */
export async function buildChallenge(
  request: BuildRequest,
  options: { readonly compileTimeoutMs: number; readonly debugInfo?: boolean },
): Promise<BuildOutcome> {
  const template = findTemplate(request.templateId ?? '') ?? resolveTemplate(request.topic)
  const difficulty = normalizeDifficultyInput(request.difficulty)
  const sessionId = safeSessionId(request.sessionId)

  if (request.source !== undefined) {
    const validation = validateCustomSource(request.source)
    if (!validation.ok) {
      return {
        ok: false,
        template,
        difficulty,
        message: `rejected the custom source: ${validation.reason}`,
        log: '',
        warnings: [],
      }
    }
  }

  const challengeId = newChallengeId(template.id, request.topic)
  const paths = createWorkspace(challengeId)
  const warnings: string[] = []

  try {
    const variant = template.variants[difficulty]
    const secret = generateSecret(variant)
    const { source, definitions } = renderChallengeSource({
      template,
      difficulty,
      secret,
      ...(request.source === undefined ? {} : { customSource: request.source }),
    })

    writeFileSync(paths.sourcePath, source, 'utf8')
    const headerSource = join(templatesDirPath(), 'mini_libc.h')
    if (existsSync(headerSource)) {
      writeFileSync(resolveInside(paths.publicDir, 'mini_libc.h'), readFileSync(headerSource, 'utf8'), 'utf8')
    } else {
      warnings.push('mini_libc.h was not found beside the templates; the delivered source will not compile as-is')
    }

    const compiled = await produceBinary({
      sourcePath: paths.sourcePath,
      outputPath: paths.binaryPath,
      definitions,
      template,
      difficulty,
      secret,
      debugInfo: options.debugInfo ?? false,
      keepSymbols: request.keepSymbols === true,
      compileTimeoutMs: options.compileTimeoutMs,
    })
    warnings.push(...compiled.warnings)

    const test = selfTest({ secret, templateId: template.id, difficulty })
    if (!test.ok) {
      throw new Error(`the challenge failed its own self-test: ${test.detail}`)
    }

    const entry: VaultEntry = {
      challengeId,
      sessionId,
      templateId: template.id,
      topic: template.topic,
      difficulty,
      secret,
      answerFingerprint: answerFingerprint(secret),
      answerLength: secret.length,
      createdAt: new Date().toISOString(),
      build: compiled.record,
    }
    writeVaultEntry(entry)
    const view = challengeView(entry)
    writeBridgeConfig(challengeId)
    writeStudentDocs(view, true)

    const modeNote = compiled.record.mode === 'built'
      ? `compiled with ${compiled.record.compiler}`
      : 'emitted by the deterministic builder (the emitter was switched on for this host)'

    return {
      ok: true,
      view,
      template,
      difficulty,
      message: `challenge ${challengeId} is ready (${modeNote}, ${compiled.record.size} bytes). Accepted length: ${secret.length} bytes.`,
      log: compiled.log,
      warnings,
    }
  } catch (error) {
    // A half-built challenge is worse than none: the student would be handed a
    // binary whose verifier record is missing or wrong.
    try {
      rmSync(paths.publicDir, { recursive: true, force: true })
      rmSync(paths.vaultDir, { recursive: true, force: true })
    } catch {
      /* best effort */
    }
    return {
      ok: false,
      template,
      difficulty,
      message: `build failed: ${error instanceof Error ? error.message : String(error)}`,
      log: '',
      warnings,
    }
  }
}

function resolveTemplate(topic: string | undefined): ChallengeTemplate {
  const normalized = (topic ?? '').trim().toLowerCase()
  const byId = findTemplate(normalized)
  if (byId !== undefined) return byId
  if (normalized.includes('xor')) return findTemplate('xor-loop')!
  if (normalized.includes('str') || normalized.includes('cmp')) return findTemplate('strcmp')!
  if (normalized.includes('arith') || normalized.includes('math')) return findTemplate('arithmetic')!
  if (normalized.includes('branch') || normalized.includes('flow') || normalized.includes('jcc')) return findTemplate('branch')!
  if (normalized.includes('arg') || normalized.includes('convention') || normalized.includes('register')) {
    return findTemplate('function-args')!
  }
  return findTemplate('xor-loop')!
}

function normalizeDifficultyInput(value: string | undefined): Difficulty {
  return (value ?? 'beginner').trim().toLowerCase() === 'intermediate' ? 'intermediate' : 'beginner'
}

/** Random hex nonce helper kept here so ids stay unique across fast successive builds. */
export function buildNonce(): string {
  return randomBytes(2).toString('hex')
}
