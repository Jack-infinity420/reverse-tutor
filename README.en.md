# Reverse Tutor — DeepSeek Harness plugin (IDA Pro edition)

> 中文文档：[README.md](README.md)

An AI reverse-engineering coach for DeepSeek Harness. The student names a topic,
the plugin builds a real ELF crackme for it, the student analyses it in IDA Pro,
and the tutor grades the *reasoning* while a deterministic verifier decides the
*answer*.

```
topic → objectives → build ELF crackme → analyse in IDA Pro → evidence
      → layered hint → verify answer → explain → weakness-tracked next challenge
```

The division of labour is the whole design:

| role | owner |
|---|---|
| teacher — decides what to ask, when to hint, how to explain | the agent, following `skills/reverse-tutor/SKILL.md` |
| laboratory — disassembly, pseudocode, cross-references | IDA Pro, driven by the student |
| facts and execution — build, inspect, run | the plugin's tools |
| referee — is this the accepted value? | a deterministic verifier, never a model |

---

## 1. What it installs

Four tools and one skill.

| tool | purpose |
|---|---|
| `reverse_build` | pick a template, generate the accepted value, inject **only** the encoded reference bytes into C, compile a real 32-bit ELF (ELF32 i386) crackme, self-test it, register the verifier record. The binary is 32-bit on purpose: it opens in IDA's 32-bit build (`ida.exe`), uses `int 0x80` for kernel calls, and is written in cdecl. Returns the challenge id, the binary path, and the accepted length — never the value. |
| `reverse_inspect` | bounded factual observation: `file`, `strings`, `readelf`, `objdump` (one function), `ida_context` (what the student's IDA session exported), `bridge` (how to export it). |
| `reverse_submit` | deterministic verdict on the final answer, plus the attempt counter and hint level. Never returns the answer. |
| `reverse_state` | the learning state: phase, attempts, hint level, five skill scores, weaknesses, and the recommended next challenge. |

The skill `reverse-tutor` carries the teaching policy: the loop, the ten rules, the
hint ladder, the rubric, the IDA workflow, and an explicit "do not" list.

---

## 2. Install

```sh
# from the directory holding this package
dsh plugin --profile <your-profile> add "file:/absolute/path/to/reverse-tutor"
```

That runs `pnpm add` in `$DSH_HOME/profiles/<profile>/` and registers the bundle,
which applies `cordis.patch.yml` and mounts the plugin in that profile's host
composition. Restart the profile — the tool list is assembled at boot.

Verify:

```sh
dsh --profile <your-profile> --dump-config | grep reverse-tutor
```

Or use the CLI directly, with no profile at all:

```sh
node lib/cli.js info        # artefact roots, compiler, runtime
node lib/cli.js selftest    # build and self-test every template
```

### Requirements

- Node **20.11+** (nothing else at runtime — the plugin has zero dependencies).
- A compiler able to produce a 32-bit Linux i386 ELF. `clang` + `lld` is
  preferred; any `gcc` that targets i386 Linux also works. On Windows, clang and
  lld fulfil this because the challenges are **freestanding** (no libc, no
  headers, raw `int 0x80` syscalls).
- Optional: `qemu-user` (`qemu-i386`) or WSL, so `reverse_submit` can verify by
  actually running the binary. Without either, verification falls back to the
  template predicate — see §7.
- Optional: IDA Pro with IDAPython, for the student's side. Labelled optional
  because the tutor still works if the student only reports what they see.

---

## 3. Artefacts and where they live

Everything is under one root, outside any session workspace:

```
~/reverse-tutor                        ← default root, override with DSH_REVERSE_TUTOR_ROOT
├── challenges/<challengeId>/          ← the student and the agent may read all of this
│   ├── challenge                      the ELF, compiled and stripped
│   ├── challenge.c                    the injected source (reference values only)
│   ├── mini_libc.h                    the freestanding support header
│   ├── README.md                      the brief: topic, objectives, how to verify
│   ├── rt_bridge.json                 where the IDA export should land
│   ├── ida_context.json              (written by the student's IDA session)
│   └── analysis/                      the student's notes
├── vault/<challengeId>/verifier.json  ← the accepted value. No tool exposes a path into this.
├── state/<sessionId>.json             ← learning state
└── tmp/                               toolchain scratch (must be ASCII-only)
```

The default root is a plain folder under the user's home directory rather than
something under `DSH_HOME`, because the challenges are *student* material: they
get opened in IDA Pro and kept between sessions, so they belong where the
operator can see them — not in a dot-directory. Point `DSH_REVERSE_TUTOR_ROOT`
somewhere else to change it, and everything below follows:

```powershell
$env:DSH_REVERSE_TUTOR_ROOT = "E:\reversing\practice"
```

The vault sits outside the session workspace on purpose. The agent's own file
tools can read anything under the workspace, so the accepted value is kept
somewhere they cannot reach, and no tool of this plugin returns a vault path.

**One deliberate exception to "no tool reads the vault":** `reverse_submit` and
`node lib/cli.js show-secret` do. The first is the verifier itself. The second
exists because an operator delivering a lab sometimes has to confirm the value;
it is not part of the model-facing surface, and nothing in the tools or the skill
tells the agent it exists.

---

## 4. Using it

Say:

```
学习 XOR
```

The agent loads the skill, calls `reverse_build`, and hands over a binary path.
In IDA Pro:

1. **File > Open** the binary from the tool result, accept the defaults, let
   auto-analysis finish. The image loads at the classic i386 base `0x08048000`
   and `.text` starts at `0x08049000`, so the tutor and the student talk about
   the same addresses.
2. Put the cursor inside the function you want to discuss.
3. Run the export script — either **File > Script file…** and choose
   `ida/reverse_tutor_export.py`, or paste into the IDA Python console:

   ```python
   exec(open(r"<package>/ida/reverse_tutor_export.py").read())
   ```

   It writes `ida_context.json` beside the binary (the path comes from
   `rt_bridge.json`, which `reverse_build` wrote). Nothing else is written and
   nothing else is read.
4. Say "exported" and the tutor will call `reverse_inspect("ida_context")`, so its
   questions match the function on your screen.

Then answer. Every conclusion needs an address, an instruction, or a data
reference behind it — the tutor will ask for one, and "it's probably the check
function" will not be accepted even when it is right.

### The hint ladder

| level | what the tutor does |
|---|---|
| 0 | asks what you currently observe |
| 1 | points at the region |
| 2 | points at the instruction or function, naming the operation but not the operand |
| 3 | asks you to trace one specific value |
| 4 | explains one local semantic relationship |
| 5 | the complete explanation — after a verified correct answer |

`reverse_submit` raises the level by one on every wrong answer. The tutor may not
raise it itself, and it may not lower it inside one challenge.

---

## 5. Templates

Ten variants across five topics. Every one is a real ELF with a real accept/reject
contract.

| template | topic | beginner | intermediate |
|---|---|---|---|
| `xor-loop` | `xor` | one-byte key broadcast over the value | four-byte repeating key, narrowed `unsigned char` comparison |
| `strcmp` | `string-comparison` | reference XORed with a 64-bit LCG keystream, stored as bytes | second keystream, stored as 32-bit words narrowed on load |
| `arithmetic` | `integer-arithmetic` | constant scale and bias over a signed `int` array | bias that advances inside the loop |
| `branch` | `control-flow` | two-branch decision, one affine transform per side | three-branch decision with an ascending-range shortcut and a derived gate |
| `function-args` | `calling-convention` | three equal 4-byte slices, one digest shape | uneven 5/4/3 split, three different digest recurrences |

### The answer is never in the delivered files

This is a hard property, asserted by `test/build.test.mjs` for every template: the
accepted value must not appear in `challenge.c` **or** in the compiled binary as a
byte sequence. Each template encodes its reference data differently, and none of
them stores the value:

- `xor-loop` stores `value[i] ^ key[i % width]`;
- `strcmp` stores `value[i] ^ keystream[i]`, where the keystream comes from a
  64-bit LCG whose seed triple the binary carries;
- `arithmetic` stores `(value[i] + i) * scale - (bias + step * i)`;
- `branch` stores a piecewise transform of each character;
- `function-args` stores three slice digests, so the value is spread across three
  functions that never see the whole string.

So `strings` and a `.rodata` dump give a student the *ciphertext*, not the answer.
Inverting it is the exercise.

### Adding a template

Create `templates/<id>/challenge.c` with a `/*__RT_DEFINES__*/` marker and a
`#define RT_SECRET_LENGTH <n>` line, a `README.md`, and one registry entry in
`src/challenge/templates.ts` carrying:

- `encode(secret)` — the reference data written into the C source,
- `accepts(secret, candidate)` — the verifier predicate, transcribed from the C
  loop,
- `transform(secret)` — the same transform as data, for the compiler-free emitter
  (or `emittable: false` and a `transform` that throws),
- `alphabet` and `secretLength`.

`test/templates.test.mjs` then cross-checks all three statements of the transform
against each other, which is what keeps them from drifting apart.

---

## 6. Security properties

Enforced in code and asserted in tests:

- **Path containment.** Every filesystem path is either computed by the plugin or
  resolved through `resolveInside()`, which rejects absolute paths, `..`, NUL, and
  sibling-prefix tricks. `challengeId` must match `[A-Za-z0-9][A-Za-z0-9._-]*`.
- **No shell.** Child processes are spawned with `shell: false` and structured
  argument vectors. A caller-supplied string never reaches a command line.
- **Bounded execution.** Compile, inspect, and verify each have a wall-clock
  timeout (20 s / 8 s / 5 s by default). `reverse_build` declares a tool-level
  `timeoutMs` as well, so a stuck build cannot hang a turn.
- **Bounded output.** Every result is clamped to 12 000 characters with an explicit
  truncation notice. `objdump` resolves one function, never a section.
- **No answer leakage.** The tool results carry a boolean, an attempt count,
  lengths, and a coarse reason. Verified by serialising the result and asserting
  the accepted value and its fingerprint are absent.
- **The verifier never calls a model.** Asserted structurally: the module contains
  no network or LLM surface at all.
- **Least privilege for the emitted program.** A challenge is freestanding, makes
  no kernel call beyond `read`/`write` on stdin/stdout (via `int 0x80`), and never
  touches the network.

### Known limitations

- The challenge binary is built and (on this host) not executed by the plugin, so
  verification falls back to the template predicate. See §7.
- `reverse_build` will accept a caller-supplied `source` for a targeted drill. It
  must contain the `{{SECRET}}` marker exactly once, so a custom source can change
  the artefact the student studies but never the acceptance rule.
- On a host whose user profile path contains non-ASCII characters, the LLVM/MSYS2
  driver cannot create its temporary object files. The plugin pins `TMP`/`TEMP` to
  an ASCII-only directory to work around it; if `DSH_HOME` is non-ASCII the
  scratch directory moves to `%SystemRoot%\Temp\reverse-tutor`.

---

## 7. Verification tiers

`reverse_submit` reports which tier produced its verdict, because a tutor that
cannot say how it knows something should not be trusted with grading.

| tier | when | how |
|---|---|---|
| `executed` | the host runs Linux ELF binaries natively | runs the binary, reads the exit code — ground truth |
| `executed-foreign` | the host reaches Linux via WSL or `qemu-user` | same, through the runtime |
| `predicate` | no runtime available | the template predicate, over the vault's value |

The predicate is package-owned code transcribed from the same C loop, and
`test/submit.test.mjs` asserts that both tiers agree on every template. So the
fallback is a real fallback: same answer, same verdict, just a different witness.

An operator who wants the strongest tier installs one of:

```sh
# Windows: qemu-user (i386), then point the plugin at it
#   DSH_REVERSE_TUTOR_RUNNER=qemu-i386
# or use WSL when a distribution is installed
#   DSH_REVERSE_TUTOR_RUNNER=wsl
```

Without either, everything still works — the challenges are also runnable by hand
on any Linux host, which is what the delivered `README.md` shows the student:

```bash
printf '%s\n' '<candidate>' | ./challenge && echo accepted
```

---

## 8. Development

```sh
npm install
npm run build        # tsc -> lib/
npm run typecheck
npm test             # build, then 62 tests, one file at a time
npm run selftest     # build + self-test all ten template variants
node lib/cli.js help
```

```
src/
├── policy.ts                 roots, limits, path containment, atomic writes
├── dsh-shim.ts               the harness surface this package uses, declared locally
├── index.ts                  plugin assembly only: tools + skill
├── verifier.ts               the deterministic referee
├── state.ts                  learning state, skills, weaknesses, next-challenge plan
├── challenge/
│   ├── templates.ts          the trusted registry: sources, encoders, predicates, specs
│   ├── build.ts              build pipeline
│   ├── toolchain.ts          compiler/runtime/disassembler discovery, bounded spawns
│   ├── elf.ts                the compiler-free ELF32 i386 emitter
│   └── workspace.ts          public workspace, private vault, IDA bridge handoff
├── inspect/
│   ├── elf.ts                ELF32/ELF64 reader, file/readelf/strings views
│   ├── x86.ts                a small i386 decoder (fallback only)
│   └── objdump.ts            function-scoped disassembly
└── tools/                    the four model-facing tools
```

### Which disassembler answers `reverse_inspect("objdump")`

`llvm-objdump` (or GNU `objdump`) from the toolchain beside the compiler, whenever
the host has one. That is the reference implementation, and it is what a student
can reproduce in their own terminal.

The bundled `src/inspect/x86.ts` decoder answers only when no tool is available —
a minimal Windows host, or a sandbox that forbids child processes. It covers the
integer subset a freestanding challenge uses: moves, `movsx`/`movzx`, arithmetic,
comparisons, `imul`/`idiv` with `cdq`, branches, `lea`, shifts, `int 0x80`.
Measured over the ten template variants it decodes every instruction it emits,
and anything it does not recognise it prints as `db 0x..` rather than guessing —
a wrong mnemonic would teach a student something false, which is worse than an
honest gap. `test/inspect.test.mjs` pins the decoder against hand-verified
encodings, and `test/e2e.test.mjs` asserts the listing a tool call returns
contains no answer.

The plugin compiles and loads with **zero runtime dependencies**: Node builtins
only, and the small slice of the harness API it uses is declared in
`src/dsh-shim.ts` rather than imported. That keeps a profile install from ever
failing on a missing transitive package.

### The schema trap this package exists to avoid

`ctx.tools.register` validates `definition.parameters` **and**
`definition.output.schema` as **raw JSON Schema** *before* inserting the
definition — while `defineTool` expects the **author-facing** DSL, in which a
field's requiredness is `required: true` *on the property*. The two forms are not
interchangeable, and the failure mode is nasty: an author-form schema passes every
offline test (none of which reaches the registry's validation) and then fails the
moment a profile boots, with

```
unsupported JSON schema: schema.properties.ok.required is not supported on type "boolean"
```

`src/tools/schema.ts` compiles one description into both projections — `author`
for `defineTool`, `raw` for the registry — and `test/e2e.test.mjs` runs each
registered definition's `parameters` and `output.schema`, exactly as the plugin
supplies them, through the harness's own `assertSupportedJsonSchema`. That test is
what caught this defect during development, and it is why this package will not
fail at boot for a reason the offline suite cannot see.

### Test suites

| file | what it protects |
|---|---|
| `policy.test.mjs` | path containment, limits, atomic writes |
| `templates.test.mjs` | encoder ↔ predicate ↔ emitter agreement; no answer in the source |
| `build.test.mjs` | real ELF output, provenance, no answer in the binary |
| `inspect.test.mjs` | every action bounded and truthful; decoder vs hand-verified encodings |
| `submit.test.mjs` | verdict determinism, no leakage, state machine invariants |
| `e2e.test.mjs` | the whole lesson through the registered tools, plus the harness schema check |
| `nocompiler.test.mjs` | the compiler-free fallback delivers a verified ELF |

Set `DSH_HARNESS_ROOT` when the harness modules live somewhere other than the
usual Windows install path; the schema check reports a diagnostic and skips when
they are unreachable.

---

## 9. Reference

- Repository: <https://github.com/Jack-infinity420/reverse-tutor>
- DeepSeek Harness: <https://github.com/deepseek-ai/deepseek-harness>
- Tool subsystem: <https://github.com/deepseek-ai/deepseek-harness/blob/master/docs/subsystems/tools.md>
- Skill package: <https://github.com/deepseek-ai/deepseek-harness/blob/master/packages/skill/README.md>
- Plugin development: <https://github.com/deepseek-ai/deepseek-harness/blob/master/docs/user/develop/basic/index.md>
- Safety: <https://github.com/deepseek-ai/deepseek-harness/blob/master/SAFETY.md>
- IDA Pro C++ SDK / Hex-Rays: <https://cpp.docs.hex-rays.com/>
- IDAPython environment: <https://hcli.docs.hex-rays.com/user-guide/ida-python-environment/>

## License

MIT — see [LICENSE](LICENSE).
