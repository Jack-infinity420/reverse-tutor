/**
 * `reverse_state` — the learning state the teaching loop reads and writes.
 *
 * The implementation spec lists exactly this surface for `state.ts`: load, save,
 * set phase, record an attempt, move the hint level, and update a skill. Exposing
 * it as a tool keeps the *teaching* decision with the agent while making the
 * *bookkeeping* deterministic and inspectable.
 *
 * Nothing here is secret. The accepted value lives in the verifier vault; this
 * tool cannot reach it and does not report anything derived from it.
 *
 * @module dsh-reverse-tutor/tools/reverse-state
 */

import { clampText } from '../policy.js'
import {
  beginChallenge,
  describeState,
  loadState,
  MAX_HINT_LEVEL,
  PHASES,
  planNextChallenge,
  recordAttempt,
  resetState,
  saveState,
  setPhase,
  setWeaknesses,
  SKILL_KEYS,
  updateHintLevel,
  updateSkill,
} from '../state.js'
import type { Phase, TutorState } from '../state.js'
import { outputSchemaPair, compileParameterSpec } from './schema.js'
import type { AuthorSchema } from './schema.js'
import { toolResult } from './render.js'
import type { ToolTextBlock } from './render.js'

/** Arguments accepted by `reverse_state`. */
export interface ReverseStateArgs {
  readonly action: 'read' | 'phase' | 'hint' | 'skill' | 'weaknesses' | 'attempt' | 'begin' | 'reset'
  readonly phase?: string
  readonly delta?: number
  readonly skill?: string
  readonly score?: number
  readonly weaknesses?: readonly string[]
  readonly challengeId?: string
  readonly topic?: string
  readonly difficulty?: string
}

/** The structured value returned to the model. */
export interface ReverseStateValue {
  readonly ok: boolean
  readonly action: string
  readonly summary: string
  readonly phase: string
  readonly challengeId: string | null
  readonly topic: string
  readonly difficulty: string
  readonly attempts: number
  readonly hintLevel: number
  readonly streak: number
  readonly skills: Readonly<Record<string, number>>
  readonly weaknesses: readonly string[]
  readonly nextTemplateId: string | null
  readonly nextDifficulty: string
  readonly nextBecause: string
  readonly message: string
}

/** Parameter schema. */
export const reverseStateParameters = {
  action: {
    type: 'string' as const,
    required: true as const,
    enum: ['read', 'phase', 'hint', 'skill', 'weaknesses', 'attempt', 'begin', 'reset'] as const,
    description:
      '`read` = current state and the next-challenge recommendation; `phase` = set the lesson phase; ' +
      '`hint` = move the hint level; `skill` = fold one 0..1 observation into a skill score; ' +
      '`weaknesses` = replace the weakness list; `attempt` = increment the attempt counter; ' +
      '`begin` = attach a new challenge to the state; `reset` = clear this session.',
  },
  phase: {
    type: 'string' as const,
    enum: PHASES as readonly string[],
    description: `For action "phase". One of: ${PHASES.join(', ')}.`,
  },
  delta: {
    type: 'integer' as const,
    description: 'For action "hint": how many levels to move, default 1. Use -1 only when you deliberately want to reduce scaffolding.',
  },
  skill: {
    type: 'string' as const,
    enum: SKILL_KEYS as readonly string[],
    description: `For action "skill". One of: ${SKILL_KEYS.join(', ')}.`,
  },
  score: {
    type: 'number' as const,
    description: 'For action "skill": this attempt\'s observation for that skill, 0..1. 2 maps to a correct rubric item, 1 to a partial one.',
  },
  weaknesses: {
    type: 'array' as const,
    items: { type: 'string' as const },
    description: `For action "weaknesses": the complete replacement list. Valid keys: ${SKILL_KEYS.join(', ')}.`,
  },
  challengeId: {
    type: 'string' as const,
    description: 'For action "begin": the challenge id returned by reverse_build.',
  },
  topic: {
    type: 'string' as const,
    description: 'For action "begin": the topic being taught.',
  },
  difficulty: {
    type: 'string' as const,
    enum: ['beginner', 'intermediate'] as const,
    description: 'For action "begin": the difficulty of that challenge.',
  },
}

/** Output schema, compiled by {@link objectSchema}. */
const reverseStateOutputSchemaFields = {
  ok: { type: 'boolean', required: true, description: 'Whether the state action was accepted.' },
  action: { type: 'string', required: true, description: 'The action that produced this result.' },
  summary: { type: 'string', required: true, description: 'The state in a compact, readable form.' },
  phase: { type: 'string', required: true, description: 'Current phase of the teaching loop.' },
  challengeId: { type: 'json', description: 'Challenge the state is tracking, or null.' },
  topic: { type: 'string', required: true, description: 'Topic currently being taught.' },
  difficulty: { type: 'string', required: true, description: 'Difficulty of the current challenge.' },
  attempts: { type: 'integer', required: true, description: 'Attempts recorded for the current challenge.' },
  hintLevel: { type: 'integer', required: true, description: 'Hint level you are licensed to give.' },
  streak: { type: 'integer', required: true, description: 'Correct answers in a row.' },
  skills: {
    type: 'object',
    required: true,
    additionalProperties: true,
    description: 'Skill name to score in 0..1.',
  },
  weaknesses: {
    type: 'array',
    required: true,
    description: 'Weak skill keys currently recorded.',
    items: { type: 'string' },
  },
  nextTemplateId: { type: 'json', description: 'Recommended next template, or null.' },
  nextDifficulty: { type: 'string', required: true, description: 'Recommended next difficulty.' },
  nextBecause: { type: 'string', required: true, description: 'Why that challenge is recommended.' },
  message: { type: 'string', required: true, description: 'One-line note about this action.' },
} satisfies Record<string, AuthorSchema>

/** One description, two projections: `author` for `defineTool`, `raw` for the registry. */
export const { author: reverseStateOutputAuthorSchema, raw: reverseStateOutputSchema } =
  outputSchemaPair(reverseStateOutputSchemaFields)

/**
 * The compiled projections `ctx.tools.register` validates.
 *
 * `register` checks `parameters` and `output.schema` as raw JSON Schema before
 * inserting the definition, so neither can be the author-facing form here.
 */
export const reverseStateCompiledOutputSchema = reverseStateOutputSchema
export const reverseStateParametersCompiled = compileParameterSpec(reverseStateParameters)

/** Render a state response for the model. */
export function renderReverseState(_args: ReverseStateArgs, value: ReverseStateValue): readonly ToolTextBlock[] {
  const lines = [
    value.summary,
    '',
    `phase: ${value.phase}`,
    `challenge: ${value.challengeId ?? '(none)'}`,
    `topic: ${value.topic || '(none)'}`,
    `difficulty: ${value.difficulty}`,
    `attempts: ${value.attempts}`,
    `hint level: ${value.hintLevel} / ${MAX_HINT_LEVEL}`,
    `streak: ${value.streak}`,
    `skills: ${Object.entries(value.skills).map(([key, score]) => `${key}=${score.toFixed(2)}`).join(' ')}`,
    `weaknesses: ${value.weaknesses.length > 0 ? value.weaknesses.join(', ') : '(none)'}`,
    '',
    `next challenge: ${value.nextTemplateId ?? '(undecided)'} / ${value.nextDifficulty}`,
    `because: ${value.nextBecause}`,
  ]
  if (value.message.length > 0) lines.push('', value.message)
  return toolResult(clampText(lines.join('\n'), 4_000))
}

/** Execute one `reverse_state` call. */
export function executeReverseState(
  args: ReverseStateArgs,
  context: { readonly sessionId: string },
): ReverseStateValue {
  let state = loadState(context.sessionId)
  let message = ''

  switch (args.action) {
    case 'read':
      break
    case 'phase': {
      const phase = (args.phase ?? '').trim().toUpperCase()
      if (!(PHASES as readonly string[]).includes(phase)) {
        return describe(state, args.action, false, `unknown phase "${String(args.phase)}"; valid: ${PHASES.join(', ')}`)
      }
      state = setPhase(state, phase as Phase)
      break
    }
    case 'hint': {
      const delta = Number.isFinite(args.delta) ? Math.trunc(args.delta as number) : 1
      state = updateHintLevel(state, delta)
      message = `hint level is now ${state.hintLevel}. Give one hint at that level and nothing further.`
      break
    }
    case 'skill': {
      const skill = (args.skill ?? '').trim()
      const score = args.score
      if (!(SKILL_KEYS as readonly string[]).includes(skill)) {
        return describe(state, args.action, false, `unknown skill "${skill}"; valid: ${SKILL_KEYS.join(', ')}`)
      }
      if (typeof score !== 'number' || !Number.isFinite(score) || score < 0 || score > 1) {
        return describe(state, args.action, false, 'score must be a number in 0..1')
      }
      state = updateSkill(state, skill, score)
      message = `${skill} is now ${state.skills[skill as keyof typeof state.skills].toFixed(2)}.`
      break
    }
    case 'weaknesses': {
      const list = Array.isArray(args.weaknesses) ? args.weaknesses : []
      const invalid = list.filter(entry => !(SKILL_KEYS as readonly string[]).includes(entry))
      if (invalid.length > 0) {
        return describe(state, args.action, false, `unknown weakness key(s): ${invalid.join(', ')}`)
      }
      state = setWeaknesses(state, list)
      message = `weaknesses recorded: ${state.weaknesses.join(', ') || '(none)'}`
      break
    }
    case 'attempt':
      state = recordAttempt(state)
      message = `attempt counter is now ${state.attempts}.`
      break
    case 'begin': {
      const challengeId = (args.challengeId ?? '').trim()
      if (challengeId === '') {
        return describe(state, args.action, false, 'action "begin" needs a challengeId from reverse_build')
      }
      const difficulty = (args.difficulty ?? 'beginner').trim().toLowerCase() === 'intermediate' ? 'intermediate' : 'beginner'
      state = beginChallenge(state, {
        challengeId,
        templateId: '',
        topic: (args.topic ?? state.topic).trim(),
        difficulty,
      })
      state = saveState({ ...state, challengeId })
      message = `state now tracks challenge ${challengeId}.`
      break
    }
    case 'reset':
      state = resetState(context.sessionId)
      message = 'learning state cleared for this session.'
      break
    default:
      return describe(state, String(args.action), false, `unsupported action "${String(args.action)}"`)
  }

  return describe(state, String(args.action), true, message)
}

/** Build the structured response from a state document. */
function describe(state: TutorState, action: string, ok: boolean, message: string): ReverseStateValue {
  const plan = planNextChallenge(state)
  return {
    ok,
    action,
    summary: describeState(state, 1_400),
    phase: state.phase,
    challengeId: state.challengeId,
    topic: state.topic,
    difficulty: state.difficulty,
    attempts: state.attempts,
    hintLevel: state.hintLevel,
    streak: state.streak,
    skills: { ...state.skills },
    weaknesses: [...state.weaknesses],
    nextTemplateId: plan.templateId,
    nextDifficulty: plan.difficulty,
    nextBecause: plan.because,
    message,
  }
}
