/**
 * Test harness shared by every suite.
 *
 * Each suite runs against its own DSH_REVERSE_TUTOR_ROOT so a test can never touch
 * a real student's challenges. Plain JavaScript on purpose: the tests exercise the
 * compiled `lib/` output the same way the harness loads it, with no transpile step
 * of its own.
 */

import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

/**
 * Point the plugin at a throwaway root and return a cleanup function.
 *
 * The root must be ASCII-only because the MSYS2/LLVM driver cannot write its
 * temporary object files into a non-ASCII path — the exact failure this plugin
 * works around in `challenge/toolchain.ts`.
 *
 * `DSH_REVERSE_TUTOR_TEST_TMP` relocates the whole tree, which is what lets the
 * suite run inside a confined workspace where the system temp directory is not
 * writable. An absolute `DSH_REVERSE_TUTOR_ROOT` is honoured as-is so an operator
 * can pin test artefacts somewhere they can inspect afterwards.
 */
export function useTemporaryRoot(label = 'rt') {
  const base = process.env['DSH_REVERSE_TUTOR_TEST_TMP']
    ?? process.env['DSH_REVERSE_TUTOR_ROOT']
    ?? (process.platform === 'win32' ? join(process.env['SystemRoot'] ?? 'C:\\Windows', 'Temp') : tmpdir())
  const root = mkdtempSync(join(base, `reverse-tutor-${label}-`))
  const previousRoot = process.env['DSH_REVERSE_TUTOR_ROOT']
  const previousTmp = process.env['DSH_REVERSE_TUTOR_TMP']
  process.env['DSH_REVERSE_TUTOR_ROOT'] = root
  process.env['DSH_REVERSE_TUTOR_TMP'] = join(root, 'tmp')
  return () => {
    if (previousRoot === undefined) delete process.env['DSH_REVERSE_TUTOR_ROOT']
    else process.env['DSH_REVERSE_TUTOR_ROOT'] = previousRoot
    if (previousTmp === undefined) delete process.env['DSH_REVERSE_TUTOR_TMP']
    else process.env['DSH_REVERSE_TUTOR_TMP'] = previousTmp
    try {
      rmSync(root, { recursive: true, force: true })
    } catch {
      /* best effort: a locked Windows artifact is not a test failure */
    }
  }
}

/** Load the compiled modules under test. */
export async function loadModules() {
  return {
    policy: await import('../lib/policy.js'),
    templates: await import('../lib/challenge/templates.js'),
    build: await import('../lib/challenge/build.js'),
    elfBuilder: await import('../lib/challenge/elf.js'),
    workspace: await import('../lib/challenge/workspace.js'),
    verifier: await import('../lib/verifier.js'),
    state: await import('../lib/state.js'),
    // Two different ELF modules: the challenge builder's emitter, and the reader
    // the inspector uses. Keep the keys distinct so a test cannot silently pick
    // the wrong one.
    inspectElf: await import('../lib/inspect/elf.js'),
    objdump: await import('../lib/inspect/objdump.js'),
    x86: await import('../lib/inspect/x86.js'),
    toolchain: await import('../lib/challenge/toolchain.js'),
    buildTool: await import('../lib/tools/reverse-build.js'),
    inspectTool: await import('../lib/tools/reverse-inspect.js'),
    submitTool: await import('../lib/tools/reverse-submit.js'),
    stateTool: await import('../lib/tools/reverse-state.js'),
    plugin: await import('../lib/index.js'),
    schema: await import('../lib/tools/schema.js'),
  }
}

/**
 * Resolve the harness's own tool registry, or `undefined` when this checkout
 * cannot see it.
 *
 * Used to validate tool schemas against the exact code that enforces them, rather
 * than against a copy of the rules. `DSH_HARNESS_ROOT` overrides the search.
 */
export async function loadHarnessValidator() {
  const { existsSync } = await import('node:fs')
  const { join } = await import('node:path')
  const { pathToFileURL } = await import('node:url')
  const roots = [
    process.env['DSH_HARNESS_ROOT'],
    'D:\\dshapp\\DSH Desktop\\resources\\app.asar.unpacked',
  ].filter(Boolean)
  for (const root of roots) {
    const entry = join(root, 'node_modules', '@deepseek-ai', 'dsh-tools', 'lib', 'index.js')
    if (!existsSync(entry)) continue
    try {
      const mod = await import(pathToFileURL(entry).href)
      if (typeof mod.assertSupportedJsonSchema === 'function') return mod
    } catch {
      /* try the next candidate */
    }
  }
  return undefined
}

/** Minimal Cordis-like context, enough for `apply()` to register its tools. */
export function createFakeContext() {
  const tools = []
  const skills = []
  const effects = []
  return {
    tools: { register: definition => { tools.push(definition); return () => {} } },
    get(name) {
      if (name === 'skills') return { register: skill => { skills.push(skill); return () => {} } }
      return undefined
    },
    effect(callback) { const dispose = callback(); effects.push(dispose); return () => {} },
    on() { return () => {} },
    logger: { info() {}, warn() {} },
    registered: tools,
    registeredSkills: skills,
    effects,
  }
}
