/**
 * `reverse_build` — turn a topic into a real, verified reverse-engineering lab.
 *
 * The tool is the only entry point that creates a challenge, and it is also the
 * boundary that keeps the accepted value away from the model: the secret is
 * generated here, written to the verifier vault, and reported back only as a
 * length. See `challenge/build.ts` for the pipeline.
 *
 * @module dsh-reverse-tutor/tools/reverse-build
 */

import { clampText, DEFAULT_LIMITS } from '../policy.js'
import { buildChallenge } from '../challenge/build.js'
import type { BuildOutcome } from '../challenge/build.js'
import { TEMPLATES } from '../challenge/templates.js'
import { beginChallenge, loadState, saveState } from '../state.js'
import { outputSchemaPair, compileParameterSpec } from './schema.js'
import type { AuthorSchema } from './schema.js'
import type { ToolTextBlock } from './render.js'

/** Arguments accepted by `reverse_build`. */
export interface ReverseBuildArgs {
  readonly topic?: string
  readonly difficulty?: string
  readonly templateId?: string
  readonly source?: string
  readonly debugInfo?: boolean
  readonly keepSymbols?: boolean
}

/** The structured value the tool returns. */
export interface ReverseBuildValue {
  readonly ok: boolean
  readonly challengeId: string | null
  readonly templateId: string
  readonly topic: string
  readonly difficulty: string
  readonly teaching: string
  readonly objectives: readonly string[]
  readonly binaryPath: string | null
  readonly sourcePath: string | null
  readonly publicDir: string | null
  readonly analysisDir: string | null
  readonly acceptedLength: number
  readonly buildMode: string
  readonly buildSize: number
  readonly warnings: readonly string[]
  readonly message: string
  readonly nextSteps: readonly string[]
}

/** Parameter schema, mirroring the implementation spec. */
export const reverseBuildParameters = {
  topic: {
    type: 'string' as const,
    description:
      'What to teach, in the student\'s words: `xor`, `strcmp`, `arithmetic`, `branch`, `function-args`, or a free phrase such as "XOR 数据流". Used to choose a template when `templateId` is omitted.',
  },
  templateId: {
    type: 'string' as const,
    description: `Exact template to build. One of: ${TEMPLATES.map(template => template.id).join(', ')}.`,
  },
  difficulty: {
    type: 'string' as const,
    enum: ['beginner', 'intermediate'] as const,
    description: 'Teaching level. `beginner` uses the simplest transform for the template; `intermediate` adds a second twist.',
  },
  source: {
    type: 'string' as const,
    description:
      'Optional custom C source for a targeted drill. It must contain the {{SECRET}} marker exactly once; the build injects the accepted value there and the template predicate still decides acceptance, so a custom source can change the artefact but never the answer.',
  },
  debugInfo: {
    type: 'boolean' as const,
    description: 'Compile with `-g`. Off by default: this is a static-analysis exercise and debug info would hand over the answer.',
  },
  keepSymbols: {
    type: 'boolean' as const,
    description: 'Skip `--strip-all`. Off by default, so the student has to locate the check function by behaviour.',
  },
}

/** Output schema, compiled by {@link objectSchema} so `required` lands correctly. */
const reverseBuildOutputSchemaFields = {
  ok: { type: 'boolean', required: true, description: 'Whether a challenge was produced.' },
  // These five are `null` on a failed build; the schema subset has no nullable
  // scalar, so they are declared as unconstrained JSON and the renderer treats a
  // non-string as absent.
  challengeId: { type: 'json', description: 'Challenge id, or null when the build failed.' },
  binaryPath: { type: 'json', description: 'Absolute path of the built ELF.' },
  sourcePath: { type: 'json', description: 'Absolute path of the injected C source.' },
  publicDir: { type: 'json', description: 'Directory the student and the agent may read.' },
  analysisDir: { type: 'json', description: 'Directory for the student\'s notes.' },
  templateId: { type: 'string', required: true, description: 'Template that produced this challenge.' },
  topic: { type: 'string', required: true, description: 'Topic the template teaches.' },
  difficulty: { type: 'string', required: true, description: '`beginner` or `intermediate`.' },
  teaching: { type: 'string', required: true, description: 'What this challenge teaches, in one line.' },
  objectives: {
    type: 'array',
    required: true,
    description: 'Observable skills the student practises.',
    items: { type: 'string' },
  },
  acceptedLength: { type: 'integer', required: true, description: 'Length of the accepted value, in bytes.' },
  buildMode: { type: 'string', required: true, description: '`built` when a compiler produced the artefact, `fallback` when the emitter did.' },
  buildSize: { type: 'integer', required: true, description: 'Size of the produced binary, in bytes.' },
  warnings: {
    type: 'array',
    required: true,
    description: 'Anything the operator should know about how the artefact was produced.',
    items: { type: 'string' },
  },
  message: { type: 'string', required: true, description: 'One-line summary for the model.' },
  nextSteps: {
    type: 'array',
    required: true,
    description: 'What the tutor should do next.',
    items: { type: 'string' },
  },
} satisfies Record<string, AuthorSchema>

/** One description, two projections: `author` for `defineTool`, `raw` for the registry. */
export const { author: reverseBuildOutputAuthorSchema, raw: reverseBuildOutputSchema } =
  outputSchemaPair(reverseBuildOutputSchemaFields)

/**
 * The compiled projections `ctx.tools.register` validates.
 *
 * `register` checks `parameters` and `output.schema` as raw JSON Schema before
 * inserting the definition, so neither can be the author-facing form here.
 */
export const reverseBuildCompiledOutputSchema = reverseBuildOutputSchema
export const reverseBuildParametersCompiled = compileParameterSpec(reverseBuildParameters)

/** Render a build outcome for the model. */
export function renderReverseBuild(_args: ReverseBuildArgs, value: ReverseBuildValue): readonly ToolTextBlock[] {
  const blocks: ToolTextBlock[] = [{ type: 'text', text: value.message }]
  if (!value.ok) return blocks

  const lines = [
    `challengeId: ${value.challengeId ?? '(none)'}`,
    `template: ${value.templateId} (${value.topic}) at ${value.difficulty}`,
    `teaching: ${value.teaching}`,
    `binary: ${value.binaryPath ?? '(none)'}`,
    `source: ${value.sourcePath ?? '(none)'}`,
    `workspace: ${value.publicDir ?? '(none)'}`,
    `analysis dir: ${value.analysisDir ?? '(none)'}`,
    `accepted length: ${value.acceptedLength} bytes`,
    `build: ${value.buildMode}, ${value.buildSize} bytes`,
    '',
    'learning objectives:',
    ...value.objectives.map(objective => `- ${objective}`),
  ]
  if (value.warnings.length > 0) {
    lines.push('', 'warnings:', ...value.warnings.map(warning => `- ${warning}`))
  }
  if (value.nextSteps.length > 0) {
    lines.push('', 'next steps:', ...value.nextSteps.map(step => `- ${step}`))
  }
  blocks.push({ type: 'text', text: clampText(lines.join('\n'), 6_000) })
  return blocks
}

/** Execute one `reverse_build` call. */
export async function executeReverseBuild(
  args: ReverseBuildArgs,
  context: { readonly sessionId: string },
): Promise<ReverseBuildValue> {
  const outcome: BuildOutcome = await buildChallenge(
    {
      ...(args.topic === undefined ? {} : { topic: args.topic }),
      ...(args.difficulty === undefined ? {} : { difficulty: args.difficulty }),
      ...(args.templateId === undefined ? {} : { templateId: args.templateId }),
      ...(args.source === undefined ? {} : { source: args.source }),
      ...(args.debugInfo === undefined ? {} : { debugInfo: args.debugInfo }),
      ...(args.keepSymbols === undefined ? {} : { keepSymbols: args.keepSymbols }),
      sessionId: context.sessionId,
    },
    { compileTimeoutMs: DEFAULT_LIMITS.compileTimeoutMs, debugInfo: args.debugInfo === true },
  )

  const base = {
    ok: outcome.ok,
    templateId: outcome.template.id,
    topic: outcome.template.topic,
    difficulty: outcome.difficulty,
    teaching: outcome.template.teaching,
    objectives: outcome.template.objectives,
    acceptedLength: outcome.view?.acceptedLength ?? 0,
    buildMode: outcome.view?.buildMode ?? 'none',
    buildSize: outcome.view?.buildSize ?? 0,
    warnings: outcome.warnings,
    message: outcome.message,
  }

  if (!outcome.ok || outcome.view === undefined) {
    return {
      ...base,
      challengeId: null,
      binaryPath: null,
      sourcePath: null,
      publicDir: null,
      analysisDir: null,
      nextSteps: [
        'Report the failure plainly and do not present a challenge.',
        'If the failure names a compiler, retry with a different template, or ask the operator to install clang/gcc.',
      ],
    }
  }

  const view = outcome.view
  // Advance the lesson state only after a successful build, so a failed build
  // cannot move the state machine into "challenge presented".
  const state = loadState(context.sessionId)
  beginChallenge(state, {
    challengeId: view.challengeId,
    templateId: view.templateId,
    topic: view.topic,
    difficulty: view.difficulty,
  })
  saveState({ ...state, challengeId: view.challengeId })

  return {
    ...base,
    challengeId: view.challengeId,
    binaryPath: view.binaryPath,
    sourcePath: view.sourcePath,
    publicDir: view.publicDir,
    analysisDir: view.analysisDir,
    buildSize: view.buildSize,
    nextSteps: [
      `Tell the student to open ${view.binaryPath} in IDA Pro and let auto-analysis finish.`,
      'Ask for a hypothesis about which function decides the outcome, and require evidence from pseudocode, assembly, cross-references, or strings.',
      'Do not read the answer out of the source file; the source carries only the encoded reference values.',
      `When the student reports what they are looking at, call reverse_inspect with action "ida_context" for challenge ${view.challengeId}.`,
      `Verify the final answer with reverse_submit for challenge ${view.challengeId}.`,
    ],
  }
}
