/**
 * `reverse_submit` — deterministic final-answer verification.
 *
 * The tool's contract is narrow on purpose. It decides one question, returns a
 * boolean and a coarse reason, and reports which mechanism produced the verdict.
 * It never returns the accepted value, never returns the reference data, and
 * never explains *why* an answer is wrong — that is the teaching layer's job, and
 * doing it here would leak the solution through the back door.
 *
 * Process-quality grading (was the reasoning evidence-backed? was the data flow
 * traced?) is deliberately *not* here: that is the agent's judgement, expressed
 * through `reverse_state`.
 *
 * @module dsh-reverse-tutor/tools/reverse-submit
 */

import { clampText, DEFAULT_LIMITS } from '../policy.js'
import { challengePaths, readVaultEntry } from '../challenge/workspace.js'
import { outputSchemaPair, compileParameterSpec } from './schema.js'
import type { AuthorSchema } from './schema.js'
import type { ToolTextBlock } from './render.js'
import { recordAttempt, recordResult, loadState, saveState, updateHintLevel, updateSkill } from '../state.js'
import { verifySubmission } from '../verifier.js'

/** Arguments accepted by `reverse_submit`. */
export interface ReverseSubmitArgs {
  readonly challengeId: string
  readonly candidate: string
  /** Self-assessment of the student's reasoning, each 0..2. */
  readonly rubric?: Readonly<Record<string, number>>
  /** Weak skill keys the agent attributes to this attempt. */
  readonly weaknesses?: readonly string[]
  /** Force the predicate tier; for hosts that cannot execute the binary. */
  readonly noExecute?: boolean
}

/** The structured value returned to the model. */
export interface ReverseSubmitValue {
  readonly correct: boolean
  readonly attempts: number
  readonly decision: string
  readonly reason: string
  readonly acceptedLength: number
  readonly submittedLength: number
  readonly hintLevel: number
  readonly message: string
  readonly nextSteps: readonly string[]
}

/** Rubric keys the agent scores, per the implementation spec. */
export const RUBRIC_KEYS = [
  'key_function',
  'argument_flow',
  'control_flow',
  'data_flow',
  'evidence_quality',
] as const

/** Parameter schema. */
export const reverseSubmitParameters = {
  challengeId: {
    type: 'string' as const,
    required: true as const,
    description: 'Challenge id returned by reverse_build.',
  },
  candidate: {
    type: 'string' as const,
    required: true as const,
    description:
      'The accepted value the student is submitting. Surrounding whitespace, one trailing newline, and one layer of matching quotes are ignored; nothing else is normalised.',
  },
  rubric: {
    type: 'object' as const,
    additionalProperties: true as const,
    description:
      'Your own 0..2 scores for the student\'s reasoning on this attempt. Keys: ' +
      `${RUBRIC_KEYS.join(', ')}. 0 = wrong, 1 = partially correct, 2 = correct. ` +
      'This is your judgement of the process; the tool only decides the final answer.',
    properties: Object.fromEntries(
      RUBRIC_KEYS.map(key => [key, { type: 'integer' as const, description: `${key}: 0, 1 or 2` }]),
    ),
  },
  weaknesses: {
    type: 'array' as const,
    items: { type: 'string' as const },
    description:
      'Skill keys to record against the student for this attempt, e.g. `dataFlow`, `controlFlow`, `assembly`, `callingConvention`, `idaUsage`.',
  },
  noExecute: {
    type: 'boolean' as const,
    description: 'Skip executing the challenge binary and use the template predicate directly. Normally unnecessary.',
  },
}

/** Output schema, compiled by {@link objectSchema}. */
const reverseSubmitOutputSchemaFields = {
  correct: { type: 'boolean', required: true, description: 'The verifier\'s verdict on the final answer.' },
  attempts: { type: 'integer', required: true, description: 'Attempts recorded for this challenge, including this one.' },
  decision: {
    type: 'string',
    required: true,
    description: '`executed`, `executed-foreign`, or `predicate` — how the verdict was reached.',
  },
  reason: { type: 'string', required: true, description: 'Coarse rejection reason, safe to act on and safe to show.' },
  acceptedLength: { type: 'integer', required: true, description: 'Length of the accepted value, in bytes.' },
  submittedLength: { type: 'integer', required: true, description: 'Length of the candidate as submitted.' },
  hintLevel: { type: 'integer', required: true, description: 'The hint level licensed by this attempt.' },
  message: { type: 'string', required: true, description: 'What the tutor should do with this verdict.' },
  nextSteps: {
    type: 'array',
    required: true,
    description: 'Concrete next actions for the teaching loop.',
    items: { type: 'string' },
  },
} satisfies Record<string, AuthorSchema>

/** One description, two projections: `author` for `defineTool`, `raw` for the registry. */
export const { author: reverseSubmitOutputAuthorSchema, raw: reverseSubmitOutputSchema } =
  outputSchemaPair(reverseSubmitOutputSchemaFields)

/**
 * The compiled projections `ctx.tools.register` validates.
 *
 * `register` checks `parameters` and `output.schema` as raw JSON Schema before
 * inserting the definition, so neither can be the author-facing form here.
 */
export const reverseSubmitCompiledOutputSchema = reverseSubmitOutputSchema
export const reverseSubmitParametersCompiled = compileParameterSpec(reverseSubmitParameters)

/** Render a verdict for the model. */
export function renderReverseSubmit(_args: ReverseSubmitArgs, value: ReverseSubmitValue): readonly ToolTextBlock[] {
  return [{ type: 'text', text: clampText(value.message, 2_000) }]
}

/** Execute one `reverse_submit` call. */
export async function executeReverseSubmit(
  args: ReverseSubmitArgs,
  context: { readonly sessionId: string },
): Promise<ReverseSubmitValue> {
  const challengeId = typeof args.challengeId === 'string' ? args.challengeId : ''

  let paths
  try {
    paths = challengePaths(challengeId)
  } catch (error) {
    return {
      correct: false,
      attempts: 0,
      decision: 'rejected',
      reason: 'invalid_challenge_id',
      acceptedLength: 0,
      submittedLength: 0,
      hintLevel: 0,
      message: `reverse_submit rejected the call: ${error instanceof Error ? error.message : String(error)}`,
      nextSteps: ['Call reverse_build and use the challengeId it returned.'],
    }
  }

  const entry = readVaultEntry(challengeId)
  if (entry === undefined) {
    return {
      correct: false,
      attempts: 0,
      decision: 'rejected',
      reason: 'unknown_challenge',
      acceptedLength: 0,
      submittedLength: 0,
      hintLevel: 0,
      message: `unknown challengeId "${challengeId}"; there is no verifier record for it`,
      nextSteps: ['Call reverse_build to create a challenge before verifying an answer.'],
    }
  }

  const raw = typeof args.candidate === 'string' ? args.candidate : ''
  if (raw.length > DEFAULT_LIMITS.maxCandidateChars) {
    return {
      correct: false,
      attempts: 0,
      decision: 'rejected',
      reason: 'candidate_too_long',
      acceptedLength: entry.answerLength,
      submittedLength: raw.length,
      hintLevel: 0,
      message:
        `the candidate is ${raw.length} characters; the accepted value is far shorter. ` +
        'Submit the recovered value itself, not your notes.',
      nextSteps: ['Ask the student for the exact string their analysis produced.'],
    }
  }

  let state = loadState(context.sessionId)
  state = recordAttempt(state)
  const attempts = state.attempts

  const verdict = await verifySubmission({
    entry,
    binaryPath: paths.binaryPath,
    candidate: raw,
    attempts,
    timeoutMs: DEFAULT_LIMITS.submitTimeoutMs,
    ...(args.noExecute === true ? { forcePredicate: true } : {}),
  })

  // Fold the rubric into the skill profile. The tool never invents a score: a
  // missing rubric leaves the profile untouched.
  const rubric = sanitizeRubric(args.rubric)
  const weaknesses = Array.isArray(args.weaknesses)
    ? args.weaknesses.filter(entry => typeof entry === 'string' && entry.length > 0)
    : []
  if (rubric !== undefined) {
    for (const [key, value] of Object.entries(rubric)) {
      const skill = rubricToSkill(key)
      if (skill === undefined) continue
      state = updateSkill(state, skill, value / 2)
    }
  }
  state = recordResult(state, {
    challengeId,
    verdict: verdict.correct ? 'correct' : 'incorrect',
    ...(rubric === undefined ? {} : { rubric }),
    ...(weaknesses.length === 0 ? {} : { weaknesses }),
  })
  if (!verdict.correct) {
    state = updateHintLevel(state, 1)
  } else {
    state = saveState({ ...state, phase: 'EXPLAIN' })
  }

  const message = verdict.correct
    ? [
        'correct: true',
        `attempts: ${attempts}`,
        `decision: ${verdict.tier}`,
        '',
        'The tool has confirmed the answer. It has not told you why, and you must not',
        'present the answer as the lesson: walk the student through the full reasoning',
        'chain from the entry point to the comparison, then update the skill profile and',
        'choose the next challenge.',
      ].join('\n')
    : [
        'correct: false',
        `attempts: ${attempts}`,
        `decision: ${verdict.tier}`,
        `reason: ${verdict.reason}`,
        `accepted length: ${verdict.acceptedLength}`,
        `submitted length: ${verdict.submittedLength}`,
        `hint level now: ${state.hintLevel}`,
        '',
        'Do not reveal the accepted value, the reference data, or the key. Give the',
        'single next hint that the recorded hint level licenses, and ask the student to',
        're-derive the value from the evidence they already have.',
      ].join('\n')

  return {
    correct: verdict.correct,
    attempts,
    decision: verdict.tier,
    reason: verdict.reason,
    acceptedLength: verdict.acceptedLength,
    submittedLength: verdict.submittedLength,
    hintLevel: state.hintLevel,
    message,
    nextSteps: verdict.correct
      ? [
          'Explain the complete chain: entry point, input buffer, loop, transform, reference data, comparison.',
          'Update the skill profile with reverse_state, then pick the next challenge.',
        ]
      : [
          `Give hint level ${state.hintLevel} only: the student has had ${attempts} attempt(s).`,
          'Ask a question rather than making a statement where the level allows it.',
          'Never state the accepted value, its length-to-content mapping, the key, or the reference bytes.',
        ],
  }
}

/** Keep only known rubric keys with values 0..2. */
function sanitizeRubric(raw: unknown): Record<string, number> | undefined {
  if (raw === null || typeof raw !== 'object') return undefined
  const source = raw as Record<string, unknown>
  const out: Record<string, number> = {}
  for (const key of RUBRIC_KEYS) {
    const value = source[key]
    if (typeof value === 'number' && Number.isFinite(value)) {
      out[key] = Math.min(2, Math.max(0, Math.trunc(value)))
    }
  }
  return Object.keys(out).length === 0 ? undefined : out
}

/** Map a rubric item to the skill dimension it measures. */
function rubricToSkill(key: string): string | undefined {
  switch (key) {
    case 'key_function':
      return 'idaUsage'
    case 'argument_flow':
      return 'callingConvention'
    case 'control_flow':
      return 'controlFlow'
    case 'data_flow':
      return 'dataFlow'
    case 'evidence_quality':
      return 'assembly'
    default:
      return undefined
  }
}
