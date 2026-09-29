/**
 * Shared rendering helpers for the three tools.
 *
 * Tool results reach the harness as lossless JSON, and the registry validates
 * every declared output schema, so the helpers here do one job only: build the
 * value the model is allowed to see, with nothing internal attached.
 *
 * @module dsh-reverse-tutor/tools/render
 */

/** One rendered content block, as the tool pipeline expects. */
export interface ToolTextBlock {
  readonly type: 'text'
  readonly text: string
}

/** Wrap a rendered string as a single text block. */
export function toolResult(text: string): readonly ToolTextBlock[] {
  return [{ type: 'text', text }]
}

/** Wrap several pre-rendered sections as text blocks. */
export function toolResultBlocks(...texts: readonly string[]): readonly ToolTextBlock[] {
  return texts.filter(text => text.length > 0).map(text => ({ type: 'text' as const, text }))
}

/** Safe string coercion for optional JSON fields. */
export function asText(value: unknown): string | undefined {
  return typeof value === 'string' && value.length > 0 ? value : undefined
}
