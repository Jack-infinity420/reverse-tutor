/**
 * Learning state: a JSON document, one per session workspace.
 *
 * This is deliberately the simplest thing that works — the implementation spec
 * is explicit that the first version must not grow a database or a framework.
 * The document answers four questions for the next turn: which phase the lesson
 * is in, how many attempts a challenge has taken, which hint level is currently
 * licensed, and which skills are weak.
 *
 * Nothing here is secret: the accepted value lives in the vault, never in the
 * state file, so the state file is safe for the agent to consider.
 *
 * @module dsh-reverse-tutor/state
 */

import { join } from 'node:path'
import { assertSafeSegment, clampText, ensureDir, readJson, resolveInside, stateRoot, writeJsonAtomic } from './policy.js'
import type { Difficulty } from './challenge/templates.js'
import { safeSessionId } from './challenge/workspace.js'

/** The lesson phases of the teaching loop. */
export type Phase =
  | 'IDLE'
  | 'UNDERSTAND_TOPIC'
  | 'CREATE_OBJECTIVES'
  | 'SELECT_TEMPLATE'
  | 'BUILD_CHALLENGE'
  | 'PRESENT_CHALLENGE'
  | 'WAITING_ANALYSIS'
  | 'GRADE'
  | 'HINT'
  | 'EXPLAIN'
  | 'UPDATE_STATE'
  | 'NEXT_CHALLENGE'

/** Every phase, in loop order; used for validation and rendering. */
export const PHASES: readonly Phase[] = [
  'IDLE',
  'UNDERSTAND_TOPIC',
  'CREATE_OBJECTIVES',
  'SELECT_TEMPLATE',
  'BUILD_CHALLENGE',
  'PRESENT_CHALLENGE',
  'WAITING_ANALYSIS',
  'GRADE',
  'HINT',
  'EXPLAIN',
  'UPDATE_STATE',
  'NEXT_CHALLENGE',
]

/** Skill dimensions tracked per student. */
export const SKILL_KEYS = [
  'assembly',
  'controlFlow',
  'dataFlow',
  'callingConvention',
  'idaUsage',
] as const

export type SkillKey = (typeof SKILL_KEYS)[number]

/** One scored attempt, kept for the trajectory the model reasons over. */
export interface AttemptRecord {
  readonly at: string
  readonly challengeId: string
  readonly level: number
  /** The agent's own 0/1/2 scores for the five rubric items. */
  readonly rubric?: Readonly<Record<string, number>>
  readonly verdict: 'correct' | 'incorrect'
  /** Weakness keys the agent attributed to this attempt. */
  readonly weaknesses?: readonly string[]
}

/** The persisted learning state. */
export interface TutorState {
  readonly version: 1
  readonly sessionId: string
  topic: string
  templateId: string | null
  phase: Phase
  challengeId: string | null
  difficulty: Difficulty
  attempts: number
  hintLevel: number
  /** Correct answers in a row, used to decide whether to raise difficulty. */
  streak: number
  skills: Record<SkillKey, number>
  weaknesses: string[]
  history: AttemptRecord[]
  updatedAt: string
}

/** Exponential smoothing factor: old evidence keeps most of its weight. */
const SMOOTHING = 0.7

/** A fresh state for a session. */
export function initialState(sessionId: string): TutorState {
  return {
    version: 1,
    sessionId: safeSessionId(sessionId),
    topic: '',
    templateId: null,
    phase: 'IDLE',
    challengeId: null,
    difficulty: 'beginner',
    attempts: 0,
    hintLevel: 0,
    streak: 0,
    skills: {
      assembly: 0.5,
      controlFlow: 0.5,
      dataFlow: 0.5,
      callingConvention: 0.5,
      idaUsage: 0.5,
    },
    weaknesses: [],
    history: [],
    updatedAt: new Date().toISOString(),
  }
}

/** Path of one session's state file. */
export function statePath(sessionId: string): string {
  const id = assertSafeSegment(safeSessionId(sessionId), 'sessionId')
  ensureDir(stateRoot())
  return resolveInside(stateRoot(), `${id}.json`)
}

/** Load state, creating a fresh document when none exists. */
export function loadState(sessionId: string): TutorState {
  const raw = readJson<TutorState>(statePath(sessionId))
  if (raw === undefined || raw.version !== 1) return initialState(sessionId)
  // Defend against a hand-edited or partially written file: every field the
  // teaching loop reads is normalised, so a malformed file degrades instead of
  // throwing inside a tool body.
  return {
    ...initialState(sessionId),
    ...raw,
    sessionId: safeSessionId(raw.sessionId ?? sessionId),
    phase: PHASES.includes(raw.phase) ? raw.phase : 'IDLE',
    attempts: Number.isFinite(raw.attempts) ? Math.max(0, Math.trunc(raw.attempts)) : 0,
    hintLevel: Number.isFinite(raw.hintLevel) ? clampHintLevel(raw.hintLevel) : 0,
    streak: Number.isFinite(raw.streak) ? Math.max(0, Math.trunc(raw.streak)) : 0,
    skills: normalizeSkills(raw.skills),
    weaknesses: Array.isArray(raw.weaknesses) ? raw.weaknesses.filter(entry => typeof entry === 'string') : [],
    history: Array.isArray(raw.history) ? raw.history.slice(-40) : [],
  }
}

/** Persist state atomically. */
export function saveState(state: TutorState): TutorState {
  const next: TutorState = { ...state, updatedAt: new Date().toISOString() }
  writeJsonAtomic(statePath(next.sessionId), next)
  return next
}

/** Hint levels the teaching policy may use. */
export const MAX_HINT_LEVEL = 5

function clampHintLevel(value: number): number {
  return Math.min(MAX_HINT_LEVEL, Math.max(0, Math.trunc(value)))
}

function normalizeSkills(raw: unknown): Record<SkillKey, number> {
  const base = initialState('x').skills
  if (raw === null || typeof raw !== 'object') return base
  const source = raw as Record<string, unknown>
  const result = { ...base }
  for (const key of SKILL_KEYS) {
    const value = source[key]
    if (typeof value === 'number' && Number.isFinite(value)) {
      result[key] = Math.min(1, Math.max(0, value))
    }
  }
  return result
}

/** Set the phase and persist. */
export function setPhase(state: TutorState, phase: Phase): TutorState {
  return saveState({ ...state, phase })
}

/** Record that a challenge has been presented and the tutor is waiting. */
export function beginChallenge(
  state: TutorState,
  challenge: { readonly challengeId: string; readonly templateId: string; readonly topic: string; readonly difficulty: Difficulty },
): TutorState {
  return saveState({
    ...state,
    topic: challenge.topic,
    templateId: challenge.templateId,
    challengeId: challenge.challengeId,
    difficulty: challenge.difficulty,
    attempts: 0,
    hintLevel: 0,
    phase: 'WAITING_ANALYSIS',
  })
}

/** Increment the attempt counter. */
export function recordAttempt(state: TutorState): TutorState {
  return saveState({ ...state, attempts: state.attempts + 1, phase: 'GRADE' })
}

/**
 * Raise the hint level, capped at {@link MAX_HINT_LEVEL}.
 *
 * The teaching policy may raise it by more than one step when an answer shows no
 * understanding at all, but it may never lower it within one challenge: the
 * student would otherwise be shown a harder hint and then have it withdrawn.
 */
export function updateHintLevel(state: TutorState, delta = 1): TutorState {
  return saveState({ ...state, hintLevel: clampHintLevel(state.hintLevel + delta), phase: 'HINT' })
}

/**
 * Fold one 0..1 observation into a skill score.
 *
 * `new = old * 0.7 + current * 0.3`. A `undefined` or out-of-range observation is
 * ignored rather than clamped, so a malformed rubric cannot silently move a
 * score to an extreme.
 */
export function updateSkill(state: TutorState, key: string, current: number): TutorState {
  if (!isSkillKey(key)) return state
  if (!Number.isFinite(current) || current < 0 || current > 1) return state
  const previous = state.skills[key]
  const next = previous * SMOOTHING + current * (1 - SMOOTHING)
  const skills = { ...state.skills, [key]: Math.min(1, Math.max(0, next)) }
  return saveState({ ...state, skills })
}

/** Whether a string names a tracked skill. */
export function isSkillKey(value: string): value is SkillKey {
  return (SKILL_KEYS as readonly string[]).includes(value)
}

/** Replace the weakness list, keeping only tracked skill keys. */
export function setWeaknesses(state: TutorState, weaknesses: readonly string[]): TutorState {
  const deduped = [...new Set(weaknesses.filter(isSkillKey))]
  return saveState({ ...state, weaknesses: deduped })
}

/** The skills currently below a mastery threshold, weakest first. */
export function weakestSkills(state: TutorState, threshold = 0.6, limit = 3): SkillKey[] {
  return SKILL_KEYS.filter(key => state.skills[key] < threshold)
    .sort((left, right) => state.skills[left] - state.skills[right])
    .slice(0, limit)
}

/** Record the outcome of a graded attempt and refresh weaknesses. */
export function recordResult(
  state: TutorState,
  result: {
    readonly challengeId: string
    readonly verdict: 'correct' | 'incorrect'
    readonly rubric?: Readonly<Record<string, number>>
    readonly weaknesses?: readonly string[]
  },
): TutorState {
  const entry: AttemptRecord = {
    at: new Date().toISOString(),
    challengeId: result.challengeId,
    level: state.hintLevel,
    verdict: result.verdict,
    ...(result.rubric === undefined ? {} : { rubric: result.rubric }),
    ...(result.weaknesses === undefined ? {} : { weaknesses: result.weaknesses }),
  }
  const weaknessSet = new Set<string>(state.weaknesses)
  for (const weakness of result.weaknesses ?? []) {
    if (isSkillKey(weakness)) weaknessSet.add(weakness)
  }
  if (result.verdict === 'correct') {
    for (const weakness of result.weaknesses ?? []) weaknessSet.delete(weakness)
  }
  const history = [...state.history, entry].slice(-40)
  return saveState({
    ...state,
    history,
    streak: result.verdict === 'correct' ? state.streak + 1 : 0,
    weaknesses: [...weaknessSet],
    phase: result.verdict === 'correct' ? 'EXPLAIN' : 'HINT',
  })
}

/**
 * Choose the next challenge shape from the current profile.
 *
 * The rule is intentionally narrow, taken straight from the spec: a weak skill
 * is re-drilled at the same difficulty, a strong one is advanced by one level.
 * It never jumps to an unrelated topic.
 */
export function planNextChallenge(state: TutorState): {
  readonly templateId: string | null
  readonly difficulty: Difficulty
  readonly because: string
} {
  const weakest = weakestSkills(state, 0.6, 1)[0]
  const mapping: Record<SkillKey, string> = {
    assembly: 'xor-loop',
    controlFlow: 'branch',
    dataFlow: 'xor-loop',
    callingConvention: 'function-args',
    idaUsage: 'strcmp',
  }
  if (weakest !== undefined) {
    return {
      templateId: mapping[weakest],
      difficulty: state.difficulty,
      because: `${weakest} is the weakest tracked skill (${state.skills[weakest].toFixed(2)}); re-drill it at the same difficulty`,
    }
  }
  if (state.streak >= 2) {
    return {
      templateId: state.templateId,
      difficulty: state.difficulty === 'beginner' ? 'intermediate' : 'intermediate',
      because: `${state.streak} correct answers in a row with no weak skill; raise the difficulty on the same topic`,
    }
  }
  return {
    templateId: state.templateId,
    difficulty: state.difficulty,
    because: 'no weak skill and no streak; repeat the topic at the same difficulty with a different twist',
  }
}

/** A compact, model-safe rendering of the state. */
export function describeState(state: TutorState, maxChars = 2_400): string {
  const lines = [
    `session: ${state.sessionId}`,
    `topic: ${state.topic || '(none)'}`,
    `phase: ${state.phase}`,
    `challenge: ${state.challengeId ?? '(none)'}`,
    `difficulty: ${state.difficulty}`,
    `attempts (this challenge): ${state.attempts}`,
    `hint level: ${state.hintLevel} / ${MAX_HINT_LEVEL}`,
    `streak: ${state.streak}`,
    `skills: ${SKILL_KEYS.map(key => `${key}=${state.skills[key].toFixed(2)}`).join(' ')}`,
    `weaknesses: ${state.weaknesses.length > 0 ? state.weaknesses.join(', ') : '(none recorded)'}`,
  ]
  const plan = planNextChallenge(state)
  lines.push(`next: ${plan.templateId ?? '(unknown)'} / ${plan.difficulty}`)
  lines.push(`next because: ${plan.because}`)
  if (state.history.length > 0) {
    lines.push('recent attempts:')
    for (const entry of state.history.slice(-5)) {
      const rubric = entry.rubric === undefined
        ? ''
        : ` rubric={${Object.entries(entry.rubric).map(([key, value]) => `${key}:${value}`).join(',')}}`
      lines.push(`  - ${entry.challengeId} ${entry.verdict} hint=${entry.level}${rubric}`)
    }
  }
  return clampText(lines.join('\n'), maxChars)
}

/** Reset all progress for a session, keeping the file in place. */
export function resetState(sessionId: string): TutorState {
  return saveState(initialState(sessionId))
}

/** Directory holding every session state file, for diagnostics. */
export function stateDirectory(): string {
  ensureDir(stateRoot())
  return join(stateRoot())
}
