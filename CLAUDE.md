# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

BlindBean is a Java 26 library that hides Homomorphic Encryption behind annotations. Developers mark fields with `@Homomorphic` and operate on encrypted values through generated wrapper proxies. Paillier is implemented in pure Java (Vector API); BFV/CKKS bridge to Microsoft SEAL 4.3 via a C++ DLL over Project Panama FFM (no JNI).

## Build & Test

Requires **JDK 26-ea** with `--enable-preview` and `--add-modules jdk.incubator.vector`. The native DLL must be built before the Java tests that exercise FHE will pass.

```bash
# 1. Build native SEAL bridge (one-time / when blindbean-fhe/src/main/native changes)
cmake -S blindbean-fhe/src/main/native -B build-native \
    -DCMAKE_TOOLCHAIN_FILE=<vcpkg-root>/scripts/buildsystems/vcpkg.cmake \
    -DVCPKG_TARGET_TRIPLET=x64-windows-static
cmake --build build-native --config Release

# 2. Build + install Java library
./mvnw clean install -B -Dblindbean.native.path=build-native

# 3. Run tests
./mvnw clean test -Dblindbean.native.path=build-native

# Single test / single method
./mvnw test -Dtest=FheNativeBridgeTest -Dblindbean.native.path=build-native
./mvnw test -Dtest=FheContextTest#guidanceEchoesTheConfiguredPathWhenSet -Dblindbean.native.path=build-native

# JMH benchmarks
./mvnw clean verify
java --enable-preview --add-modules jdk.incubator.vector -jar target/benchmarks.jar
```

On Windows use `mvnw.cmd` and `-Dblindbean.native.path=build-native/Release` (MSVC puts artifacts under the config subdir; non-Windows builds do not). `JAVA_HOME` must point at the JDK 26 install — if it points at an older JDK, surefire forks that JVM and the run dies on "class file version 70.0".

The `blindbean-example` module is a separate Maven project demonstrating consumer usage of `@Homomorphic` / `@BlindEntity` and the generated wrappers — build the main library with `install` first so the example can resolve it.

Tests that touch BFV/CKKS need the native library; pure-Paillier, processor and JUnit-extension tests do not. Consumer-style tests should use `@BlindBeanTest` (below) rather than hand-rolling context setup.

## Module layout (JPMS reactor)

The build is a Maven reactor of six library modules, each a real named module with a
`module-info.java`, plus a BOM and a thin aggregate:

| Maven artifact | JPMS module | packages | requires |
|---|---|---|---|
| `blindbean-annotations` | `se.deversity.blindbean.annotations` | annotations | — |
| `blindbean-core` | `se.deversity.blindbean.core` | core | annotations |
| `blindbean-fhe` | `se.deversity.blindbean.fhe` | fhe (+ native under `src/main/native`) | core |
| `blindbean-runtime` | `se.deversity.blindbean.runtime` | math, context, async | fhe, `jdk.incubator.vector` |
| `blindbean-processor` | `se.deversity.blindbean.processor` | processor | annotations only; `provides` Processor |
| `blindbean-junit` | `se.deversity.blindbean.junit` | junit | runtime, junit-api |
| `blindbean` (pom) | — | — | aggregate; keeps the classpath coordinate |
| `blindbean-bom` (pom) | — | — | version management |

- **`math`, `context`, `async` ship together as `-runtime`** because `BlindMath` (in `math`) dispatches
  into `context`, and `context` uses the Paillier types back — a cycle a module boundary cannot cut,
  and `BlindMath`'s package cannot move (public API + guardrail). Do not try to separate them.
- **`processor` depends only on `annotations`** — it emits runtime calls as text. Keep it that way:
  a consumer's compile path must not pull the runtime, native, or the Vector API.
- **All tests live in `blindbean-tests`** (classpath, depends on everything). New tests go there, not
  in the library modules — most are integration tests that cross module boundaries.
- **A module-path consumer** (see `module-path-tests`) `requires se.deversity.blindbean.runtime`, puts
  `blindbean-processor` on the `--processor-module-path`, and needs
  `--enable-native-access=se.deversity.blindbean.fhe` for BFV/CKKS. Classpath consumers use the
  `blindbean` aggregate (`<type>pom</type>`). That test is the guard against a wrong `exports`.
- The `@AI*` guardrail annotations are `requires static` everywhere (SOURCE retention). The vibetags
  guardrail *generator* (vibetags-processor, RC6) now **runs across the reactor**, driven by
  `-Avibetags.root=${maven.multiModuleProjectDirectory}` on the compiler plugin. Each annotated
  module owns a `.claude/rules/` of **role-grouped** topic files (`paths:` frontmatter), grouped by
  that module's `.vibetags-roles`; Claude Code auto-loads them when you open a matching source file.
  The root `.vibetags-root-index` marker makes the generated block in **`CLAUDE.md` a lean index** —
  one pointer per module to its `.claude/rules/`, not the full merge. `GEMINI.md` keeps the
  sidecar-**merged** block (Gemini has no scoped-rules feature, so it needs the embedded copy). These
  are **generated from the `@AI*` annotations, not hand-edited**: change the annotations, recompile.
  `blindbean-processor` overrides the compiler config, so it re-declares the vibetags path (pinned to
  `${vibetags.version}`) and the reactor-root arg itself, or its guardrails drop out of the output.

## Architecture (three layers)

1. **Developer layer — `se.deversity.blindbean.annotations` + `se.deversity.blindbean.processor.HomomorphicProcessor`.** An annotation processor (registered via AutoService) runs at compile time, reads `@BlindEntity` / `@Homomorphic` classes, resolves the `type()` TypeMirror (e.g. `String.class`, `long[].class`, `boolean.class`), and generates `<Entity>BlindWrapper` source files. Proxies are **source-generated, not reflective** — do not add runtime reflection or bytecode weaving. The processor must also enforce algebraic boundaries: math operations (`add*`/`multiply*`) are omitted for String / boolean fields because they would corrupt the encoded value.

2. **Java FFM layer — `se.deversity.blindbean.fhe` + `se.deversity.blindbean.math` + `se.deversity.blindbean.context`.** `FheContext` owns a native `BlindBeanContext*` as an opaque `MemorySegment` and is `AutoCloseable`; callers must use try-with-resources or leak native heap. Its `bfv()`/`ckks()` factories route the native call through the package-private `initNative(Supplier)` helper, which converts linkage failures (`UnsatisfiedLinkError`, `ExceptionInInitializerError`, `NoClassDefFoundError`) into an `FheException` carrying `nativeLoadGuidance()` — a message stating the detected OS/arch, whether `blindbean.native.path` is set and where it pointed, the exact `-D` flag, the Windows `Release/` subdir gotcha and the cmake build command. Keep new native entry points behind that helper so the first-run failure stays actionable; `FheNativeBridge` itself is locked. `FheNativeBridge` resolves all ~15 native symbols **once at class-load** via `SymbolLookup.loaderLookup()` into `MethodHandle` statics (`MH_ADD`, `MH_MULTIPLY`, etc.) — any new native call must follow the same pattern. `FheCiphertextNative` wraps individual ciphertext handles and provides `toBlindCiphertext()` / `fromBlindCiphertext()` for serialization across the FFM boundary. `BlindMath` is the dispatcher that routes operations to either the pure-Java Paillier (`se.deversity.blindbean.math`, Vector API / SIMD) path or the native FHE path via `BlindContext`.

3. **Test-support layer — `se.deversity.blindbean.junit`.** `@BlindBeanTest` (class-level) + `BlindBeanExtension` manage the `BlindContext` lifecycle per test method: `init()` before each test, `clear()` after, with `scheme` / `polyModulusDegree` / `ckksScale` attributes additionally booting the native BFV or CKKS context. The extension walks parent contexts so `@Nested` classes inherit the enclosing annotation, and `@ExtendWith(BlindBeanExtension.class)` alone behaves like the Paillier defaults. This ships in the **main** jar (that is why `junit-jupiter-api` is scope `provided`, not `test`) so consumers get it with the library. Prefer it over hand-rolled `@BeforeEach`/`@AfterEach` context wiring, in this repo's tests and in the example module.

4. **Native layer — `blindbean-fhe/src/main/native/blindbean_fhe.{h,cpp}`.** Single DLL (`blindbean_fhe.dll`) built statically against SEAL + CRT (`x64-windows-static` triplet) so deployment needs no extra runtime. All exported symbols use `extern "C"` and `__declspec(dllexport)` on Windows. State lives in a `BlindBeanContext` struct on the C++ heap; Java never sees SEAL types directly. BFV auto-relinearizes after multiply; CKKS auto-relinearizes and rescales. Parameters target 128-bit security per the HomomorphicEncryption.org standard — **do not lower poly modulus degree below 8192 or weaken coeff modulus without an explicit request**.

## Runtime flags

Every `java`/`surefire` invocation against this codebase needs, at minimum:

```
--enable-preview
--add-modules jdk.incubator.vector
--enable-native-access=ALL-UNNAMED
```

These are already wired into `maven-compiler-plugin` and `maven-surefire-plugin` in `pom.xml`. When running the JMH jar or the example module directly, pass them on the command line.

The native library location is controlled by the `blindbean.native.path` system property (read by `FheNativeBridge` when loading symbols). Tests will fail fast if the DLL cannot be found there.

## CI

GitHub Actions runs three jobs: a fast Java-only gate on Linux+macOS (everything that does not need the DLL), a native build matrix on Linux/macOS/Windows publishing the shared library as an artifact, and the full Maven test suite on Windows against the published `blindbean_fhe.dll`. Changes touching `blindbean-fhe/src/main/native/**` require the native matrix to stay green before the Windows test job can consume the artifact.

**Tests that need the DLL carry `@Tag("native")`.** The fast gate runs `-DexcludedGroups=native`; a local or Windows run leaves `excludedGroups` empty and executes everything. If you add a test that boots a BFV/CKKS context, tag it — an untagged one breaks the Linux gate. Tag the `@Nested` class, not the outer one, when only part of a suite needs native (see `BlindMathTest`, `BlindBeanExtensionTest`).

Both the fast gate and the Windows suite upload JaCoCo XML to **Codecov**, which enforces a patch-coverage gate on pull requests: new/changed lines must be covered, so ship tests with the code. Coverage is only collected where the code actually runs — the FHE bridge can *only* be covered by the Windows report, so if that upload breaks, `FheContext`/`FheCiphertextNative` read 0% and the gate fails on code that is in fact well tested. Two traps, both hit for real:

- The Codecov action input is **`files:`**, not `file:` (v7 renamed it and silently ignores the old name — check the run log for `Unexpected input(s) 'file'`).
- A gate that runs only a subset of tests produces a report where everything else reads 0%. Codecov merges uploads, so a *missing* upload — not a missing test — is the usual reason a well-covered file shows 0%. Regenerate the suspect job's report locally (`mvn clean test` with the same flags, then read `target/site/jacoco/jacoco.xml`) before writing tests for a gap that may not exist. Note JaCoCo's agent **appends** to `jacoco.exec`, so always `clean` first or a previous run's data will inflate the numbers.

## Supported field types

The scheme is decided by the field's type, and the processor fails the build on a wrong pairing.
`@Homomorphic(type = X.class)` names the *plaintext* type; the field itself is always a `String`
holding hex.

| Type | Scheme | Arithmetic | Encoding |
|---|---|---|---|
| `byte`/`short`/`int`/`long`/`BigInteger` (+ boxed) | PAILLIER | add, sub | `BigInteger.valueOf` |
| `BigDecimal` | PAILLIER | add, sub | unscaled integer at a fixed `scale()` |
| `String` | PAILLIER | none | UTF-8 bytes as an unsigned magnitude |
| `byte[]` | PAILLIER | none | bytes with a `0x01` length marker (a BigInteger drops leading zeros) |
| `boolean` | PAILLIER | none | 0 / 1 |
| `Instant`, `LocalDate` | PAILLIER | none | epoch millis / epoch day |
| `Duration` | PAILLIER | add, sub | millis |
| `float`/`double` (+ boxed) | CKKS | add, sub, mul | scalar |
| `float[]`, `double[]` | CKKS | add, sub, mul | slot vector |
| `long[]`, `int[]`, `short[]` | BFV | add, sub, mul | slot vector |

Rules worth knowing before adding another type:

- **Arithmetic is generated only where it means something.** `Instant` and `LocalDate` are *points* —
  adding two of them is nonsense — so no `addX` is emitted. `Duration` is a *quantity*, so it is.
  Strings and blobs get none either: adding two encodings corrupts them.
- **Paillier is signed, but only through `decryptSigned`.** Its plaintext space is Z_n, so a raw
  `decrypt` returns a residue and `encrypt(-5)` comes back as `n - 5`. Every *numeric* decode in the
  generated code goes through `PaillierMath.decryptSigned` (balanced representation). Strings and
  `byte[]` must keep using plain `decrypt` — they are unsigned magnitudes, and a blob with the top
  bit set would otherwise read as negative.
- **A BFV slot is ~20 bits, not 64.** `PlainModulus::Batching(degree, 20)` gives t ≈ 1,032,193, so a
  slot holds about ±516,000. `FheContext.encryptLongArray` now rejects anything larger — before the
  guard SEAL reduced it mod t and returned a plausible wrong number, and a single out-of-range entry
  corrupted every other slot in the vector. `maxSlotValue()` reports the limit.
- **CKKS has degree/2 slots**, not degree (complex-conjugate symmetry), and is approximate — never
  use it for money. `BigDecimal` on Paillier is the exact option.
- `byte[]` is deliberately a Paillier **blob**, not a BFV vector; use `short[]`/`int[]` for small
  integer vectors.

**Composition (`@BlindNested`).** A field whose type is itself a `@BlindEntity` gets an accessor
returning that entity's wrapper (`order.customer().subBalance(...)`), so the whole inner API is
reachable without wrapping by hand at every call site. It writes through to the same object; a null
nested entity yields a null wrapper. Explicit by design — the processor does not hunt for
`@BlindEntity`-typed fields on its own, and a field may not be both `@Homomorphic` and
`@BlindNested`.

**Records are unsupported by construction**, not by omission: the wrapper stores each ciphertext with
`entity.setX(hex)`, and a record's components are final. Supporting them means a different generated
API that returns a new record rather than mutating one. The processor rejects them with that reason
rather than a bare "only applies to classes".

## Releasing

Coordinates are `se.deversity:blindbean` (packages live under `se.deversity.blindbean.*`). Cutting a release is tagging one — `.github/workflows/release.yml` fires on `v*`:

```bash
mvn versions:set -DnewVersion=0.2.0   # pom must already say 0.2.0
git tag v0.2.0 && git push origin v0.2.0
```

The tag **must** match `<version>` in `pom.xml`; the workflow refuses to run otherwise, because a Release labelled v0.2.0 shipping a 0.1.0 jar is worse than no release. SNAPSHOT versions are refused outright.

The workflow builds the three native libraries, runs the full SEAL-backed suite on Windows, signs, uploads to Maven Central, and attaches the jar + all three natives + `SHA256SUMS.txt` to a GitHub Release. **`autoPublish` is `false`** — the bundle uploads and waits for a human to press Publish on central.sonatype.com, because a Central release is irreversible (a version can never be replaced or withdrawn). Central needs four secrets — `MAVEN_GPG_PRIVATE_KEY`, `MAVEN_GPG_PASSPHRASE`, `CENTRAL_USERNAME`, `CENTRAL_PASSWORD` — and until they are set the workflow **skips Central and still cuts the GitHub Release**, so a tag can never half-publish. See the header of `release.yml`.

Central mandates POM `name`/`description`/`url`/`licenses`/`developers`/`scm` plus signed jar, **sources jar and javadoc jar** — a missing javadoc jar is the classic cause of a release that uploads then silently fails validation. All of that lives in the `release` profile, which is off by default so an ordinary `mvn install` never tries to sign anything. Verify it without publishing:

```bash
mvn -Prelease package -DskipTests -Dgpg.skip=true   # should produce -sources and -javadoc jars
```

Javadoc needs `--enable-preview`/`--add-modules` passed explicitly (`additionalJOptions`) or it refuses to parse the sources it is documenting.

## Further reading

`docs/ARCHITECTURE.md` has PlantUML class/sequence diagrams of the FHE multiply flow and the full FFM bridge parameter table. `README.md` has the annotation-level quickstart, the consumer-build flags and scheme parameter choices. `docs/SECURITY-AND-LIMITATIONS.md` states what each scheme does and does not provide (no encrypted comparisons, malleability, CKKS approximation), the noise-budget rules and key-rotation guidance — consult it before changing crypto-adjacent behavior or advising users. `docs/DX-REVIEW.md` tracks the developer-experience backlog (publish + bundle natives, LTS baseline, Spring/JPA modules) with status.

<!-- VIBETAGS-START -->
<!-- VIBETAGS-MODULE: blindbean-core -->
Guardrails for module `blindbean-core` are maintained in that module's own files, in the scoped rules under `blindbean-core/.claude/rules/` (loaded automatically when you open a matching source file). Consult those for this module's full guardrails.
<!-- VIBETAGS-MODULE-END: blindbean-core -->
<!-- VIBETAGS-MODULE: blindbean-fhe -->
Guardrails for module `blindbean-fhe` are maintained in that module's own files, in the scoped rules under `blindbean-fhe/.claude/rules/` (loaded automatically when you open a matching source file). Consult those for this module's full guardrails.
<!-- VIBETAGS-MODULE-END: blindbean-fhe -->
<!-- VIBETAGS-MODULE: blindbean-junit -->
Guardrails for module `blindbean-junit` are maintained in that module's own files, in the scoped rules under `blindbean-junit/.claude/rules/` (loaded automatically when you open a matching source file). Consult those for this module's full guardrails.
<!-- VIBETAGS-MODULE-END: blindbean-junit -->
<!-- VIBETAGS-MODULE: blindbean-processor -->
Guardrails for module `blindbean-processor` are maintained in that module's own files, in the scoped rules under `blindbean-processor/.claude/rules/` (loaded automatically when you open a matching source file). Consult those for this module's full guardrails.
<!-- VIBETAGS-MODULE-END: blindbean-processor -->
<!-- VIBETAGS-MODULE: blindbean-runtime -->
Guardrails for module `blindbean-runtime` are maintained in that module's own files, in the scoped rules under `blindbean-runtime/.claude/rules/` (loaded automatically when you open a matching source file). Consult those for this module's full guardrails.
<!-- VIBETAGS-MODULE-END: blindbean-runtime -->
<!-- VIBETAGS-END -->
