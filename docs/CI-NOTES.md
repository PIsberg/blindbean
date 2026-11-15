# CI notes

`ci.yml` runs, in order of what they cost you when they break:

| Job | What it proves | Legs |
|---|---|---|
| `java-gate` | everything that does not need the native library compiles and passes, on every supported JDK and OS | 6 (JDK 25/26 × Linux/macOS/Windows) |
| `javadoc` | the javadoc jar the release profile attaches actually builds | 1 |
| `reproducible-build` | two clean builds of the same source produce byte-identical jars | 1 |
| `dependency-hygiene` | enforcer rules pass (gate); declared vs used dependencies (**report only**, see below) | 1 |
| `dependency-review` | no PR-introduced dependency carries a high advisory | PRs only |
| `native-build-matrix` | the SEAL bridge compiles, and publishes the shared library as an artifact | 3 |
| `native-sanitizers` | the FFM boundary is clean under ASan + UBSan | 1 |
| `full-windows` | the whole suite, native tests included, against the published DLL | 2 (JDK 25/26) |

Changes touching `blindbean-fhe/src/main/native/**` require the native matrix to stay green before
the Windows test job can consume the artifact.

Two more workflows are deliberately *not* wired into `ci.yml`: `security-scan.yml` (OWASP
dependency-check, weekly + on demand) and `mutation-testing.yml` (PIT, `workflow_dispatch` only).
Both are slow, and the first changes verdict without the code changing — a gate that goes red
because a CVE was published overnight teaches people to ignore red.

## Supply-chain and security workflows

| Workflow | What it proves | Runs on |
|---|---|---|
| `fuzz.yml` | a 60 s Jazzer campaign against `BlindContext.loadKeys` finds nothing | push to main, PRs |
| `actions-lock.yml` | every action is in `actions.lock` and every locked commit is reachable from its upstream tag | push to main, PRs |
| `codeql.yml` | CodeQL static analysis | push, PRs, weekly |
| `scorecards.yml` | publishes the OpenSSF Scorecard behind the README badge | push to main, weekly |

**FindSecBugs** rides inside the SpotBugs gate in `java-gate` (`findsecbugs-plugin` in the root
pom's SpotBugs config), so a security finding fails `verify` like any other bug. Every suppression
is in `config/spotbugs/exclude.xml` with its reason. The native loader (`FheNativeBridge.loadNativeLibrary`
and `NativeLibraryLocator`) has no suppression since #254 was fixed.

**Fuzzing.** `KeyBundleLoadFuzzTest` is a Jazzer `@FuzzTest`. In `java-gate` it runs in regression
mode: it replays any stored inputs under `blindbean-tests/src/test/resources/.../KeyBundleLoadFuzzTestInputs/`
and generates nothing. `fuzz.yml` sets `JAZZER_FUZZ=1`, which turns the same method into a fuzzer.
Locally:

```bash
JAZZER_FUZZ=1 ./mvnw -pl blindbean-tests -am test -DexcludedGroups=native \
  -Dtest='KeyBundleLoadFuzzTest#loadKeysOnArbitraryBytes' -Dsurefire.failIfNoSpecifiedTests=false
```

The fuzz target mutates a valid bundle it generates in-process, rather than a committed seed: a
serialized key bundle in the repo would be a key fixture, which the `KeyBundle` privacy guardrail
rules out. Jazzer's working corpus lands in `blindbean-tests/.cifuzz-corpus/` (gitignored). A
crashing input it writes under `...Inputs/` *does* belong in the commit: it is a mutated bundle of
a throwaway 512-bit test key, and committing it is what makes it a regression test.

**Actions lockfile.** After changing any `uses:` line, run `gh actions-lock --no-narrow` and commit
`.github/workflows/actions.lock`. Never drop `--no-narrow`: without it the tool rewrites
`@<sha> # vX.Y.Z` to `@vX.Y.Z`, which Scorecard counts as unpinned.

**Branch protection.** `main` is guarded by the repository ruleset "main: OpenSSF Scorecard branch
protection" (Settings → Rules → Rulesets; `gh api repos/PIsberg/blindbean/rulesets`): no deletion,
no force push, changes only through a PR with 2 approvals including the code owner
(`.github/CODEOWNERS`), stale approvals dismissed on push, the last push approved, and every check
of `ci.yml`, `codeql.yml`, `fuzz.yml` and `actions-lock.yml` passing on a branch that is up to date
with `main`. The repository-admin role may bypass it **for pull requests only**: with one
maintainer nobody else can approve, so merging is `gh pr merge <N> --merge --admin`. Direct pushes to
`main` are refused for everyone. Measured with the Scorecard 5.6.0 CLI and an admin token:
Branch-Protection went 0 → 8; with CODEOWNERS on `main` it should reach 9. The tenth point needs the
rules to bind admins, that is, deleting the bypass, which only makes sense with a second reviewer.
Renaming a job in those workflows renames its check: update the ruleset's required checks in the same
PR, or every later PR waits on a check that no longer exists. And because the ruleset requires an
up-to-date branch, a PR stacked on another one needs `main` merged in after its predecessor lands,
so its CI runs again.

**SBOM.** `cyclonedx-maven-plugin` writes `target/<artifactId>-<version>-cyclonedx.json` (CycloneDX
1.6, compile + runtime scope) for every published module at `package` and attaches it, so it ships
to Central beside each jar and onto the GitHub Release. `reproducible-build` hashes jars only, so
the SBOM's per-build serial number does not trip it.

## The JDK matrix

The build compiles at `${maven.compiler.release}` (26 by default) and each matrix leg overrides it
to its own JDK, so the sources are checked against *that* JDK's API rather than merely recompiled.
Reproduce a leg locally with `./mvnw verify -Dmaven.compiler.release=25`.

Two things make this work, and both will silently undo it if reverted:

- **No `--enable-preview` anywhere.** Preview classfiles load on exactly the JDK that produced them,
  so a preview build cannot have a matrix at all. Nothing in the tree needs preview; see
  `RUNTIME-FLAGS.md`.
- **Nothing names a `SourceVersion.RELEASE_nn` constant.** `HomomorphicProcessor` overrides
  `getSupportedSourceVersion()` returning `latestSupported()` instead of carrying
  `@SupportedSourceVersion(RELEASE_26)`. An annotation value must be a compile-time constant, so the
  literal form fails to compile against any older JDK's `javax.lang.model` with "an enum annotation
  value must be an enum constant".

**The floor is JDK 22, not 21.** `java.lang.foreign` was a preview API in 21 and `Arena.allocateFrom`
did not exist there, so `blindbean-fhe` does not compile against 21 at any flag setting. Adding a 21
leg is a rewrite of the FFM bridge, not a CI change.

## Reproducible builds

`project.build.outputTimestamp` in `pom.xml` is what makes `reproducible-build` pass — without it
jar entry timestamps come from the clock and every build differs. If that job goes red, run the two
builds locally and `diff` the checksums before assuming CI is at fault; the usual cause is a newly
added plugin that stamps something non-deterministic into the jar.

## OWASP dependency-check needs a secret

`security-scan.yml` skips the scan, loudly, when the `NVD_API_KEY` repository secret is absent —
NVD rate-limits anonymous feed downloads badly enough that the job would otherwise hang for hours.
**A skipped scan is not a passed scan.** The job writes that distinction into the step summary on
purpose. Get a key at <https://nvd.nist.gov/developers/request-an-api-key>.

## Native-tagged tests

**Tests that need the DLL carry `@Tag("native")`.** The fast gate runs `-DexcludedGroups=native`; a
local or Windows run leaves `excludedGroups` empty and executes everything. If you add a test that
boots a BFV/CKKS context, tag it — an untagged one breaks the Linux gate. Tag the `@Nested` class,
not the outer one, when only part of a suite needs native (see `BlindMathTest`,
`BlindBeanExtensionTest`).

## `@AsyncTest` budgets: `timeoutMs` covers every round

**`timeoutMs` is one budget for all `invocations` rounds together, not a per-round limit.** When it
runs out mid-test the failure reads like a deadlock ("Invocation round timed out: 4/20 threads
completed within 186ms ... A thread may be stuck before the test body"), but the small number is
the budget left when the last round started, not a hang. Work that is serialized on a lock, like
every `FheContext` call on `nativeLock`, costs `threads x invocations x body time` no matter how
many threads you add. Size it from the surefire report (`time=` per testcase in
`blindbean-tests/target/surefire-reports/TEST-*.xml`) and keep the test under about a third of its
budget: `FheAsyncConcurrencyTest.concurrentBfvOperationsAreThreadSafe` used 43.7 s of 60 s and went
red under load (#259), and now uses about 13 s. Before adding rounds, check the test can fail at
all: that one passed with the lock removed (#268).

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
- `AGENTS.md` has no granular sibling, so it keeps the sidecar-**merged** block. `GEMINI.md`
  collapsed to an index of `.gemini/rules/` from RC10 up to 1.2.x. Since VibeTags 1.3 (#763, "a lean
  root GEMINI.md") an indexed reactor root's `GEMINI.md` carries the safety sections inline and no
  index, and a clean build with the cache deleted no longer rewrites `.gemini/rules/` (checked at
  1.4.2; the files there keep their 1.2.0-era timestamps). Gemini CLI never read that directory
  (VibeTags #669). Whether to delete the leftover `.gemini/rules/` is tracked in #255.
  Expect a build to add a rule file whenever a module gains its first indexed guardrail; that is
  generated output and belongs in the commit.
- `AGENTS.md` is only *written* by VibeTags when it is the sole AI config file present
  (`ServiceRegistry` treats it as a hand-written pointer otherwise). In this repo it stays a pointer.
- `blindbean-processor` overrides the compiler config, so it must re-declare the vibetags processor
  path (pinned to `${vibetags.version}`) **and** the `-Avibetags.root` arg, or its guardrails
  silently drop out of the output.

The generated markdown is **not hand-edited** — change the annotations and recompile. Full reference
lives in the bundled `vibetags-usage` skill; keep the vendored copies under `.claude/skills/` and
`.gemini/skills/` in sync with the pinned `${vibetags.version}`.

## Vendored skills

Two skills are vendored, both into `.claude/skills/` and `.gemini/skills/`, and both are copies of
an upstream file rather than generated output:

| Skill | Upstream | Must match |
|---|---|---|
| `vibetags-usage` | `PIsberg/vibetags` `.claude/skills/vibetags-usage/SKILL.md` | `${vibetags.version}` in `pom.xml` |
| `async-test-lib` | `PIsberg/async-test-lib` `.claude/SKILL.md` | the `async-test-lib` version in `blindbean-tests/pom.xml` |

Bump the dependency and the vendored copy in the same change. A skill that documents a version the
build does not resolve is worse than no skill: it is a plausible-looking API reference for methods
that will not compile. That is not hypothetical, the `async-test-lib` copy sat at `0.5.0` while the
dependency moved to `1.7.0-RC3`.

Upstream version labels are a claim, not the artifact. The 1.7.0-RC5 skill marks
`LazyConstantMisuseDetector`, `FinalFieldMutationDetector` and `SharedKdfDetector` as `1.8.0+`;
all three are in the 1.7.0-RC5 jar with `AsyncTestContext` accessors. Check the jar before
concluding a detector is unavailable:

```bash
javap -cp <async-test-lib.jar> se.deversity.asynctest.AsyncTestContext | grep Detector
```
