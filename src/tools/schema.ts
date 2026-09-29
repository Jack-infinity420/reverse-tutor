/**
 * Tool schema helpers.
 *
 * The harness's schema DSL is author-facing, not raw JSON Schema: per-property
 * `required: true` is what marks a field required, and the registry moves those
 * flags into the enclosing object's `required` array. The subtle part is that an
 * *output* schema passed straight through as raw JSON Schema is rejected — not
 * because it is malformed, but because `required` must not sit on the property it
 * describes, and `json` (an author-only node) is not a legal `type`.
 *
 * Handing the original schema to `tools.register` therefore fails the moment a
 * profile boots, while the offline tests still pass because they never build the
 * real rendered JSON Schema. These helpers compile the output schemas the way the
 * registry does, so both paths agree.
 *
 * @module dsh-reverse-tutor/tools/schema
 */

/** One author-facing value-schema node. */
export interface AuthorSchema {
  readonly type?: 'string' | 'number' | 'integer' | 'boolean' | 'null' | 'array' | 'object' | 'json'
  readonly description?: string
  readonly title?: string
  readonly default?: unknown
  readonly examples?: readonly unknown[]
  readonly enum?: readonly (string | number)[]
  readonly const?: string | number | boolean | null
  readonly required?: boolean
  /**
   * Whether an `object` node accepts fields beyond the ones declared.
   *
   * A sibling of `properties` on the same node — the author form the harness's own
   * `defineTool` uses. `register` wants the compiled raw form instead, where the
   * field map sits beside this flag rather than nested inside it; see
   * {@link compilePropertyMap}.
   */
  readonly additionalProperties?: boolean
  /**
   * Field map for an `object` node.
   *
   * The harness accepts `additionalProperties: true` in this map as a shorthand for
   * an open object such as the rubric, so both spellings are supported here.
   */
  readonly properties?: Record<string, AuthorSchema>
  readonly items?: AuthorSchema
  readonly oneOf?: readonly AuthorSchema[]
}

/** The compiled, raw JSON Schema projection of an author schema. */
export type JsonSchema = Record<string, unknown>

/**
 * Compile one author node into the enforced raw JSON Schema subset.
 *
 * The author-only `json` node becomes an annotation-only schema, which is how a
 * field that accepts `null` or any other JSON value is declared here.
 *
 * For an `object` node the compiled result carries `properties` (the field map)
 * and `additionalProperties` as siblings — the shape the harness enforces. The
 * author form of the same thing is `{ type: 'object', additionalProperties: true,
 * properties: { … } }`, which is what the harness's own `defineTool` consumes, so
 * `additionalProperties` inside the field map is also accepted as a shorthand.
 */
export function compileValueSchema(spec: AuthorSchema): JsonSchema {
  const node: JsonSchema = {}
  copyAnnotations(spec, node)

  if (spec.oneOf !== undefined) {
    node['oneOf'] = spec.oneOf.map(branch => compileValueSchema(branch))
    return node
  }
  if (spec.type === 'json' || spec.type === undefined) return node

  node['type'] = spec.type
  if (spec.enum !== undefined) node['enum'] = [...spec.enum]
  if (spec.const !== undefined) node['const'] = spec.const
  if (spec.items !== undefined) node['items'] = compileValueSchema(spec.items)
  if (spec.type === 'object') {
    const fields: Record<string, AuthorSchema> = {}
    let open = spec.additionalProperties === true
    for (const [key, value] of Object.entries(spec.properties ?? {})) {
      // The shorthand: an `additionalProperties` entry inside the field map, whose
      // value is a boolean rather than a schema node.
      if (key === 'additionalProperties' && typeof value === 'boolean') {
        open = value
        continue
      }
      fields[key] = value as AuthorSchema
    }
    node['additionalProperties'] = open
    if (Object.keys(fields).length > 0) node['properties'] = compilePropertyMap(fields).properties
  }
  return node
}

/**
 * Compile a per-property map into an object schema.
 *
 * Per-property `required: true` is collected into the object's `required` array —
 * the single rule the registry enforces — and each field is compiled with its own
 * annotations.
 */
export function compilePropertyMap(properties: Record<string, AuthorSchema>): {
  properties: Record<string, JsonSchema>
  required?: string[]
} {
  const compiled: Record<string, JsonSchema> = {}
  const required: string[] = []
  for (const [key, spec] of Object.entries(properties)) {
    if (spec.required === true) required.push(key)
    compiled[key] = compileValueSchema(spec)
  }
  return { properties: compiled, ...(required.length === 0 ? {} : { required }) }
}

/**
 * Build the author-facing, object-rooted output schema.
 *
 * This is the shape `defineTool` consumes: per-property `required: true`, and
 * `json` as a node type. Hand it to `defineTool` and it compiles to exactly what
 * {@link compileOutputSchema} produces — which is why both projections come from
 * one description rather than two hand-maintained copies.
 */
export function authorOutputSchema(properties: Record<string, AuthorSchema>): AuthorSchema {
  return { type: 'object', additionalProperties: false, properties }
}

/**
 * Build the raw, object-rooted output schema the tool registry validates.
 *
 * `required` is collected from each property's own `required: true`, and
 * `additionalProperties: false` is declared so a tool whose value gains a field
 * fails loudly instead of silently extending the contract.
 */
export function compileOutputSchema(properties: Record<string, AuthorSchema>): JsonSchema {
  const { properties: compiled, required } = compilePropertyMap(properties)
  return {
    type: 'object',
    additionalProperties: false,
    properties: compiled,
    ...(required === undefined ? {} : { required }),
  }
}

/**
 * The two projections of one output description.
 *
 * `author` is for `defineTool` (and for tests that compile it); `raw` is for
 * `ctx.tools.register`. Keeping them derived from one object is what stops the
 * model-facing contract and the enforced contract from drifting apart.
 */
export function outputSchemaPair(properties: Record<string, AuthorSchema>): {
  author: AuthorSchema
  raw: JsonSchema
} {
  return { author: authorOutputSchema(properties), raw: compileOutputSchema(properties) }
}

/**
 * Compile a tool's author-facing parameter map into raw JSON Schema.
 *
 * `ctx.tools.register` validates `definition.parameters` **and**
 * `definition.output.schema` as raw JSON Schema before inserting the definition,
 * so both have to be compiled here. The author-facing forms are what `defineTool`
 * consumes; keeping both projections derived from one description is what stops
 * the model-facing contract from drifting away from the enforced one — and what
 * stops a profile boot from failing while the offline tests still pass.
 */
export function compileParameterSpec(parameters: Record<string, AuthorSchema>): JsonSchema {
  const { properties, required } = compilePropertyMap(parameters)
  return {
    type: 'object',
    properties,
    ...(required === undefined ? {} : { required }),
  }
}

function copyAnnotations(spec: AuthorSchema, node: JsonSchema): void {
  if (spec.description !== undefined) node['description'] = spec.description
  if (spec.title !== undefined) node['title'] = spec.title
  if (spec.default !== undefined) node['default'] = spec.default
  if (spec.examples !== undefined) node['examples'] = [...spec.examples]
}
