# CI notes

GitHub Actions runs three jobs: a fast Java-only gate on Linux+macOS (everything that does not need
the DLL), a native build matrix on Linux/macOS/Windows publishing the shared library as an artifact,
and the full Maven test suite on Windows against the published `blindbean_fhe.dll`. Changes touching
`blindbean-fhe/src/main/native/**` require the native matrix to stay green before the Windows test
job can consume the artifact.

## Native-tagged tests

**Tests that need the DLL carry `@Tag("native")`.** The fast gate runs `-DexcludedGroups=native`; a
local or Windows run leaves `excludedGroups` empty and executes everything. If you add a test that
boots a BFV/CKKS context, tag it — an untagged one breaks the Linux gate. Tag the `@Nested` class,
not the outer one, when only part of a suite needs native (see `BlindMathTest`,
`BlindBeanExtensionTest`).

## Codecov — two traps, both hit for real

Both the fast gate and the Windows suite upload JaCoCo XML to **Codecov**, which enforces a
patch-coverage gate on pull requests: new/changed lines must be covered, so ship tests with the code.
Coverage is only collected where the code actually runs — the FHE bridge can *only* be covered by the
Windows report, so if that upload breaks, `FheContext`/`FheCiphertextNative` read 0% and the gate
fails on code that is in fact well tested.

- The Codecov action input is **`files:`**, not `file:` (v7 renamed it and silently ignores the old
  name — check the run log for `Unexpected input(s) 'file'`).
- A gate that runs only a subset of tests produces a report where everything else reads 0%. Codecov
  merges uploads, so a *missing* upload — not a missing test — is the usual reason a well-covered
  file shows 0%. Regenerate the suspect job's report locally (`mvn clean test` with the same flags,
  then read `target/site/jacoco/jacoco.xml`) before writing tests for a gap that may not exist. Note
  JaCoCo's agent **appends** to `jacoco.exec`, so always `clean` first or a previous run's data will
  inflate the numbers.

## VibeTags guardrail generation

The `@AI*` guardrail annotations are `requires static` everywhere (SOURCE retention). The generator
(`vibetags-processor`, pinned to `${vibetags.version}`) runs across the reactor, driven by
`-Avibetags.root=${maven.multiModuleProjectDirectory}` on the compiler plugin.

- Each annotated module owns a `.claude/rules/` of role-grouped topic files (`paths:` frontmatter),
  grouped by that module's `.vibetags-roles`. Claude Code auto-loads them when you open a matching
  source file.
- The root `.vibetags-root-index` marker (VibeTags ≥ 1.0.0-RC6) keeps the generated block in
  `CLAUDE.md` and `.github/copilot-instructions.md` short: each module gets a pointer to its scoped
  rules rather than the full merge. Since 1.0.0-RC8 the safety families are *also* rendered inline
  in the root block, above that pointer: `locked_files`, `audit_requirements`, `ignored_elements`,
  `pii_guardrails`, `core_elements`, `security_elements`, `public_api_elements` and
  `contextual_instructions`. `blindbean-core` and `blindbean-junit` declare none of those, so they
  stay pointer-only; `blindbean-fhe`, `blindbean-processor` and `blindbean-runtime` gained an inline
  block at the RC8 bump. A root block that grows on a version bump is that change, not a regression.
- `.claudeignore` no longer carries a block for a module with no exclusions, so it shrank by four
  empty module regions at RC8. Same cause, same conclusion.
- `GEMINI.md` and `AGENTS.md` have no granular sibling in this repo, so they keep the
  sidecar-**merged** block. RC8 added `.gemini/rules/` as an opt-in; creating that directory would
  collapse `GEMINI.md` to an index too. It is deliberately not created here.
- `AGENTS.md` is only *written* by VibeTags when it is the sole AI config file present
  (`ServiceRegistry` treats it as a hand-written pointer otherwise). In this repo it stays a pointer.
- `blindbean-processor` overrides the compiler config, so it must re-declare the vibetags processor
  path (pinned to `${vibetags.version}`) **and** the `-Avibetags.root` arg, or its guardrails
  silently drop out of the output.

The generated markdown is **not hand-edited** — change the annotations and recompile. Full reference
lives in the bundled `vibetags-usage` skill; keep the vendored copies under `.claude/skills/` and
`.gemini/skills/` in sync with the pinned `${vibetags.version}`.
