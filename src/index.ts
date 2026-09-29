/**
 * `dsh-reverse-tutor` \u2014 the DeepSeek Harness Reverse Tutor (IDA Pro edition).
 *
 * Assembly only. Every behaviour lives in a module beside this file:
 *
 * - `challenge/` builds and stores a challenge,
 * - `verifier.ts` decides the final answer,
 * - `state.ts` keeps the lesson state,
 * - `tools/` is the model-facing surface,
 * - `policy.ts` holds the sandbox rules.
 *
 * The plugin registers four tools and one skill, and declares exactly the two
 * services it consumes.
 *
 * @module dsh-reverse-tutor
 */

import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { DEFAULT_LIMITS, tutorRoot } from './policy.js'
import type { CordisPlugin, PluginContext, SkillRegistration, ToolExecution } from './dsh-shim.js'
import { executeReverseBuild, renderReverseBuild, reverseBuildCompiledOutputSchema, reverseBuildParametersCompiled } from './tools/reverse-build.js'
import type { ReverseBuildArgs } from './tools/reverse-build.js'
import { executeReverseInspect, renderReverseInspect, reverseInspectCompiledOutputSchema, reverseInspectParametersCompiled } from './tools/reverse-inspect.js'
import type { ReverseInspectArgs } from './tools/reverse-inspect.js'
import { executeReverseSubmit, renderReverseSubmit, reverseSubmitCompiledOutputSchema, reverseSubmitParametersCompiled } from './tools/reverse-submit.js'
import type { ReverseSubmitArgs } from './tools/reverse-submit.js'
import { executeReverseState, renderReverseState, reverseStateCompiledOutputSchema, reverseStateParametersCompiled } from './tools/reverse-state.js'
import type { ReverseStateArgs } from './tools/reverse-state.js'
import { safeSessionId } from './challenge/workspace.js'
import { ensureDir } from './policy.js'

/** Cordis plugin name; also the id used by the bundle patch. */
export const name = 'reverse-tutor'

/** Services this plugin consumes. */
export const inject = ['tools'] as const

/** Name of the teaching skill this plugin publishes. */
export const SKILL_NAME = 'reverse-tutor'

/** Resolve the session id for a tool call. */
function sessionIdOf(exec: { readonly agent?: { readonly session: { readonly id?: string } } }): string {
  return safeSessionId(exec.agent?.session?.id)
}

/** Load the shipped teaching skill body. */
export function skillBody(): string {
  const here = new URL('.', import.meta.url)
  const root = join(decodeURIComponent(here.pathname.replace(/^\/([A-Za-z]:)/, '$1')), '..')
  return readFileSync(join(root, 'skills', SKILL_NAME, 'SKILL.md'), 'utf8')
}

/** Strip YAML frontmatter from a skill document. */
export function stripFrontmatter(text: string): string {
  const source = text.replace(/^\uFEFF/, '').replace(/\r\n/g, '\n')
  if (!source.startsWith('---')) return source
  const end = source.indexOf('\n---', 3)
  return end === -1 ? source : source.slice(end + 4).trimStart()
}

/** The skill registration this plugin publishes. */
export function reverseTutorSkill(): SkillRegistration {
  return {
    name: SKILL_NAME,
    description:
      'Interactive reverse-engineering tutor for guided IDA Pro practice: generates a real ELF crackme for a topic, ' +
      'makes the student do the reasoning, requires evidence, verifies the final answer deterministically, and gives ' +
      'one layered hint at a time. Use when the user wants to learn or practise reverse engineering, asks to be ' +
      'tutored on a binary-analysis topic such as XOR, strcmp, arithmetic, branches or calling conventions, or wants ' +
      'a crackme to analyse in IDA Pro.',
    whenToUse:
      'Load this when the goal is *learning* reverse engineering rather than getting a binary analysed: "teach me XOR", ' +
      '"瀛︿範 XOR", "give me a crackme", "practise IDA", or when the user is working through a challenge the tutor built.',
    content: stripFrontmatter(skillBody()),
    // `runtime` is the harness's reserved provider name for skills registered by a
    // plugin, and its loader requires `source` to be a string. Without this the
    // registration is rejected at load time with
    // `loaded skill "reverse-tutor" source must be a string`.
    source: 'runtime',
    invocation: { modelInvocable: true, userInvocable: true },
    provider: 'reverse-tutor',
    resourceBase: { kind: 'directory', path: join(tutorRoot(), 'challenges') },
  }
}

/**
 * Register the tools and the skill.
 *
 * @param ctx - the plugin context; `tools` is a declared dependency, `skills` is
 *   optional so a deployment without a skill registry still gets the tools.
 * @param config - reserved for deployment overrides.
 */
export function apply(ctx: PluginContext, config?: unknown): void {
  void config
  const sessionId = (exec: { readonly agent?: { readonly session: { readonly id?: string } } }): string => sessionIdOf(exec)

  // The challenge root is created eagerly so the first tool call never races the
  // filesystem and the operator can see where artefacts will land.
  try {
    ensureDir(tutorRoot())
  } catch {
    // A read-only DSH_HOME is not fatal here: the failure will surface with a
    // clearer message from the build tool itself.
  }

  // Every `output.schema` below is the AUTHOR-facing projection (`…OutputAuthorSchema`),
  // because this object is a `defineTool` option object: the registry compiles the
  // author DSL and moves each per-property `required: true` into the enclosing
  // object's `required` array. Passing the compiled raw schema here instead fails
  // the moment a profile boots, with `schema.properties.<field>.required is not
  // supported`. `test/e2e.test.mjs` runs both projections through the harness's own
  // validator so the two can never drift apart.

  ctx.tools.register({
    name: 'reverse_build',
    description:
      'Build a reverse-engineering lab for one topic: choose a template, generate the accepted value, inject only ' +
      'the encoded reference bytes into C source, compile a real 32-bit ELF (ELF32 i386) crackme, self-test it, and ' +
      'register the verifier record. The binary is x86 32-bit on purpose: it opens in IDA\'s 32-bit build (ida.exe), ' +
      'uses `int 0x80` for kernel calls, and is written in cdecl. Returns the challengeId, the binary path to open in ' +
      'IDA Pro, and the accepted length \u2014 never the accepted value. Call this when starting a lesson or moving to ' +
      'the next challenge.',
    parameters: reverseBuildParametersCompiled,
    output: {
      schema: reverseBuildCompiledOutputSchema,
      render: (args: ReverseBuildArgs, value: unknown) =>
        renderReverseBuild(args, value as never),
    },
    presentCall: (args: ReverseBuildArgs) => ({
      card: 'generic',
      title: `Build ${args.templateId ?? args.topic ?? 'xor'} challenge`,
      kind: 'other',
      rawInput: { topic: args.topic ?? null, templateId: args.templateId ?? null, difficulty: args.difficulty ?? 'beginner' },
    }),
    // Three attempts at the compile ceiling, plus the strip and self-test that
    // follow a success: the harness must not cut off a retry that is still working.
    timeoutMs: DEFAULT_LIMITS.compileTimeoutMs * 3 + 15_000,
    isConcurrencySafe: () => false,
    async execute(args: ReverseBuildArgs, exec: ToolExecution) {
      return executeReverseBuild(args, { sessionId: sessionId(exec) })
    },
  } as never)

  ctx.tools.register({
    name: 'reverse_inspect',
    description:
      'Observe a built challenge factually, within a bounded budget. Actions: `file` (format and analysis anchors), ' +
      '`strings` (printable runs with file offsets), `readelf` (program and section headers), `objdump` (instruction ' +
      'listing for ONE function, by address or name), `ida_context` (what the student\'s IDA Pro session exported), ' +
      '`bridge` (the exact steps for the student to export it). Use this instead of asking the student to paste ' +
      'disassembly, and prefer `ida_context` so the questions match the function they are actually reading.',
    parameters: reverseInspectParametersCompiled,
    output: {
      schema: reverseInspectCompiledOutputSchema,
      render: (args: ReverseInspectArgs, value: unknown) =>
        renderReverseInspect(args, value as never),
    },
    presentCall: (args: ReverseInspectArgs) => ({
      card: 'generic',
      title: `Inspect ${args.action} (${args.challengeId ?? '?'})`,
      kind: 'other',
      rawInput: { action: args.action, challengeId: args.challengeId ?? null, functionName: args.functionName ?? null },
    }),
    timeoutMs: DEFAULT_LIMITS.inspectTimeoutMs + 10_000,
    isConcurrencySafe: (args: ReverseInspectArgs) => args.action !== 'ida_context',
    async execute(args: ReverseInspectArgs, exec: ToolExecution) {
      void exec
      return executeReverseInspect(args)
    },
  } as never)

  ctx.tools.register({
    name: 'reverse_submit',
    description:
      'Verify a student\'s final answer deterministically. Executes the built challenge with the candidate on stdin ' +
      'where this host can run a Linux ELF, and otherwise checks the template predicate directly; both are ' +
      'deterministic and neither calls a model. Returns `correct`, the attempt count, the decision tier, and a coarse ' +
      'reason \u2014 never the accepted value, the reference data, or the key. Also records your own 0..2 rubric scores and ' +
      'any weak skill keys, and advances the hint level by one on a wrong answer.',
    parameters: reverseSubmitParametersCompiled,
    output: {
      schema: reverseSubmitCompiledOutputSchema,
      render: (args: ReverseSubmitArgs, value: unknown) =>
        renderReverseSubmit(args, value as never),
    },
    presentCall: (args: ReverseSubmitArgs) => ({
      card: 'generic',
      title: `Verify answer for ${args.challengeId ?? '?'}`,
      kind: 'other',
      rawInput: { challengeId: args.challengeId ?? null, candidateLength: typeof args.candidate === 'string' ? args.candidate.length : 0 },
    }),
    timeoutMs: DEFAULT_LIMITS.submitTimeoutMs + 10_000,
    isConcurrencySafe: () => false,
    async execute(args: ReverseSubmitArgs, exec: ToolExecution) {
      return executeReverseSubmit(args, { sessionId: sessionId(exec) })
    },
  } as never)

  ctx.tools.register({
    name: 'reverse_state',
    description:
      'Read and update the tutor\'s learning state: which phase the lesson is in, how many attempts the current ' +
      'challenge has taken, the hint level you are licensed to give, the five skill scores, and the recorded ' +
      'weaknesses. `read` also returns the recommended next challenge and why. Use `skill` and `weaknesses` to record ' +
      'your own judgement of the student\'s reasoning \u2014 the tool never guesses it.',
    parameters: reverseStateParametersCompiled,
    output: {
      schema: reverseStateCompiledOutputSchema,
      render: (args: ReverseStateArgs, value: unknown) =>
        renderReverseState(args, value as never),
    },
    timeoutMs: 5_000,
    isConcurrencySafe: (args: ReverseStateArgs) => args.action === 'read',
    execute(args: ReverseStateArgs, exec: ToolExecution) {
      return executeReverseState(args, { sessionId: sessionId(exec) })
    },
  } as never)

  const skills = ctx.get<{ register(skill: SkillRegistration): () => void }>('skills')
  if (skills !== undefined) {
    ctx.effect(() => skills.register(reverseTutorSkill()))
  }
}

/** Cordis plugin module shape. */
const plugin: CordisPlugin = { name, inject, apply }
export default plugin
