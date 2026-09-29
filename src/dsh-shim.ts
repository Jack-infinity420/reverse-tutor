/**
 * The narrow slice of the DeepSeek Harness plugin surface this package uses.
 *
 * Declared locally instead of imported so the plugin compiles and loads with
 * zero runtime dependencies on harness internals. The shapes mirror the
 * `defineTool` option object and the `skills` registry contract published by
 * this harness version.
 *
 * @module dsh-reverse-tutor/dsh-shim
 */

/** One scalar-or-structured value schema node, in the author-facing DSL. */
export interface ValueSchemaSpec {
  readonly type?: 'string' | 'number' | 'integer' | 'boolean' | 'null' | 'array' | 'object' | 'json'
  readonly description?: string
  readonly title?: string
  readonly enum?: readonly (string | number)[]
  readonly const?: string | number | boolean | null
  readonly required?: boolean
  readonly properties?: Record<string, ValueSchemaSpec>
  readonly items?: ValueSchemaSpec
  readonly additionalProperties?: boolean
  readonly oneOf?: readonly ValueSchemaSpec[]
}

/** One rendered block in a tool result. */
export interface ToolContentBlock {
  readonly type: 'text' | string
  readonly text?: string
}

/** The author-facing tool definition accepted by `defineTool`. */
export interface ToolDefinition<Args, Value> {
  readonly name: string
  readonly description: string
  readonly parameters: Record<string, ValueSchemaSpec>
  readonly timeoutMs?: number
  readonly output: {
    readonly schema: ValueSchemaSpec
    readonly render: (args: Args, value: Value) => readonly ToolContentBlock[]
    readonly presentationMeta?: (args: Args, value: Value) => unknown
  }
  readonly execute: (args: Args, exec: ToolExecution) => Promise<Value> | Value
  readonly presentCall?: (args: Args) => unknown
  readonly presentResult?: (args: Args, value: Value) => unknown
  readonly isConcurrencySafe?: (args: Args) => boolean
  readonly finalizeContent?: (exec: ToolExecution, result: unknown) => unknown
}

/** Execution context handed to a tool body. */
export interface ToolExecution {
  readonly callId: string
  readonly name: string
  readonly signal: AbortSignal
  readonly agent?: { readonly session: { readonly id?: string } }
}

/** The tool registry seam this plugin registers into. */
export interface ToolsService {
  register(definition: unknown): () => void
}

/** Invocation policy carried by a skill summary. */
export interface SkillInvocationPolicy {
  readonly modelInvocable: boolean
  readonly userInvocable: boolean
}

/** A skill definition as accepted by `skills.register`. */
export interface SkillRegistration {
  readonly name: string
  readonly description: string
  readonly whenToUse?: string
  readonly content: string
  /**
   * Discovery locator the registry stores alongside the definition.
   *
   * The harness's loader rejects a registration whose `source` is not a string, and
   * a runtime registration is owned by the reserved `runtime` provider, so that is
   * the value every runtime skill carries.
   */
  readonly source?: string
  readonly invocation?: SkillInvocationPolicy
  readonly provider?: string
  readonly resourceBase?: { readonly kind: 'directory'; readonly path: string } | { readonly kind: 'opaque'; readonly description: string }
}

/** The skills registry seam this plugin registers a skill into. */
export interface SkillsService {
  register(skill: SkillRegistration): () => void
}

/** Minimal Cordis plugin context for a host-plane plugin. */
export interface PluginContext {
  readonly tools: ToolsService
  readonly skills?: SkillsService
  readonly logger?: { info(message: string): void; warn(message: string): void }
  get<T = unknown>(name: string): T | undefined
  effect(callback: () => unknown): () => void
  on(event: string, listener: (...args: never[]) => unknown): () => void
}

/** A Cordis plugin module body. */
export interface CordisPlugin {
  readonly name: string
  readonly inject: readonly string[]
  readonly apply: (ctx: PluginContext, config?: unknown) => void
}
