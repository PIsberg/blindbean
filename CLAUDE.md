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
  guardrail *generator* is **not** run in the reactor (per-module it fragments `GEMINI.md`), so the
  committed `GEMINI.md`/`CLAUDE.md` guardrail blocks are now hand-maintained until regenerated once.

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
<!-- # Generated by VibeTags | https://github.com/PIsberg/vibetags -->
<project_guardrails>
  <locked_files>
    <file path="se.deversity.blindbean.context.KeyBundle.serialVersionUID">
      <reason>Serialization UID — altering this invalidates all persisted key bundles and breaks key import/export across versions</reason>
    </file>
    <file path="se.deversity.blindbean.fhe.FheNativeBridge">
      <reason>Direct Memory FFM JNI mapping. Avoid breaking SEAL bridge architecture.</reason>
    </file>
    <file path="se.deversity.blindbean.math.PaillierKeyPair.serialVersionUID">
      <reason>Serialization UID — changing this breaks deserialization of persisted KeyBundle files</reason>
    </file>
  </locked_files>
  <contextual_instructions>
    <file path="se.deversity.blindbean.fhe.FheContext.initNative(java.util.function.Supplier&lt;java.lang.foreign.MemorySegment&gt;)">
      <focus>Every native context entry point must be routed through this helper so the missing-library failure — the first error most new users hit — stays actionable</focus>
      <avoids>Calling FheNativeBridge init symbols directly from a factory, which would surface a bare UnsatisfiedLinkError with no remediation guidance</avoids>
    </file>
    <file path="se.deversity.blindbean.processor.HomomorphicProcessor">
      <focus>Strictly maintain high-performance AST compilation speed</focus>
      <avoids>Heavy internal object allocations</avoids>
    </file>
  </contextual_instructions>

  <audit_requirements>
    <file path="se.deversity.blindbean.async.BlindAsync">
      <vulnerability_check>Thread Safety</vulnerability_check>
      <vulnerability_check>Resource Leaks</vulnerability_check>
      <vulnerability_check>Shutdown race conditions</vulnerability_check>
    </file>
    <file path="se.deversity.blindbean.context.BlindContext">
      <vulnerability_check>Resource Leaks</vulnerability_check>
      <vulnerability_check>Thread Safety</vulnerability_check>
      <vulnerability_check>Context Closure failures</vulnerability_check>
    </file>
    <file path="se.deversity.blindbean.fhe.FheCiphertextNative">
      <vulnerability_check>Resource Leaks</vulnerability_check>
      <vulnerability_check>Memory Segment lifecycle</vulnerability_check>
      <vulnerability_check>Double-free</vulnerability_check>
    </file>
  </audit_requirements>

<rule>
  If you are asked to modify any file listed in <audit_requirements>, you must first silently analyze your proposed code for the listed <vulnerability_check> items. If your code introduces these vulnerabilities, you must rewrite it before displaying it to the user.
</rule>
  <ignored_elements>
    <file path="se.deversity.blindbean.async.BlindAsync.INIT_LOCK"/>
    <file path="se.deversity.blindbean.processor.HomomorphicProcessor.isIntegral(java.lang.String)"/>
    <file path="se.deversity.blindbean.processor.HomomorphicProcessor.isFloatingPoint(java.lang.String)"/>
    <file path="se.deversity.blindbean.processor.HomomorphicProcessor.getPrimitiveType(java.lang.String)"/>
    <file path="se.deversity.blindbean.processor.HomomorphicProcessor.getBoxedType(java.lang.String)"/>
  </ignored_elements>

<rule>Never reference or suggest changes to any element listed in <ignored_elements>. Treat these as if they do not exist.</rule>
  <pii_guardrails>
    <element path="se.deversity.blindbean.context.BlindRotation">
      <reason>Holds two generations of private key material — never log the key pairs, the native key payloads, the decrypted plaintext, or expose them in fixtures</reason>
    </element>
    <element path="se.deversity.blindbean.context.KeyBundle">
      <reason>Contains serialized Paillier private key material and SEAL key bytes — never log, transmit in plaintext, or expose field values in suggestions or test fixtures</reason>
    </element>
    <element path="se.deversity.blindbean.math.PaillierKeyPair">
      <reason>Contains RSA-family private key components (lambda, mu) — never log values, include in test fixtures, or expose in suggestions</reason>
    </element>
  </pii_guardrails>

<rule>
  Never include runtime values of elements listed in <pii_guardrails> in logs, console output, external API calls, test fixtures, mock data, or code suggestions. Treat their values as strictly confidential.
</rule>
  <core_elements>
    <element path="se.deversity.blindbean.context.BlindContext">
      <sensitivity>High</sensitivity>
      <note>Well-tested core functionality. Make changes with extreme caution.</note>
    </element>
    <element path="se.deversity.blindbean.fhe.FheContext">
      <sensitivity>High</sensitivity>
      <note>Well-tested core functionality. Make changes with extreme caution.</note>
    </element>
    <element path="se.deversity.blindbean.fhe.FheNativeBridge">
      <sensitivity>High</sensitivity>
      <note>Well-tested core functionality. Make changes with extreme caution.</note>
    </element>
  </core_elements>

<rule>Elements listed in <core_elements> are well-tested core components. Make changes with extreme caution and verify comprehensive test coverage before proposing modifications.</rule>
  <performance_constraints>
    <element path="se.deversity.blindbean.fhe.FheContext.encryptLongArray(long[])">
      <constraint>Strict time/space complexity constraints apply. Suboptimal complexity is unacceptable.</constraint>
    </element>
    <element path="se.deversity.blindbean.fhe.FheContext.multiply(java.lang.foreign.MemorySegment,java.lang.foreign.MemorySegment)">
      <constraint>Strict time/space complexity constraints apply. Suboptimal complexity is unacceptable.</constraint>
    </element>
    <element path="se.deversity.blindbean.math.PaillierMath">
      <constraint>Encryption/decryption are modPow-heavy over large BigIntegers — never introduce extra copies, unnecessary allocations, or redundant modular reductions on the hot path</constraint>
    </element>
    <element path="se.deversity.blindbean.math.PaillierVectorized">
      <constraint>Strict time/space complexity constraints apply. Suboptimal complexity is unacceptable.</constraint>
    </element>
    <element path="se.deversity.blindbean.math.PaillierVectorized.batchAddBigInteger(java.math.BigInteger[],java.math.BigInteger[],java.math.BigInteger)">
      <constraint>Strict time/space complexity constraints apply. Suboptimal complexity is unacceptable.</constraint>
    </element>
  </performance_constraints>

<rule>Elements listed in <performance_constraints> are on a hot path. Never introduce O(n²) or worse complexity. Always reason about time and space complexity before suggesting changes.</rule>
  <contract_signatures>
    <element path="se.deversity.blindbean.fhe.FheCiphertextNative">
      <reason>Serialization format and handle lifecycle are part of the public FFM contract; do not change method signatures</reason>
    </element>
    <element path="se.deversity.blindbean.fhe.FheContext">
      <reason>Public FHE API consumed by generated BlindWrapper classes; any signature change requires processor regeneration and a major version bump</reason>
    </element>
    <element path="se.deversity.blindbean.junit.BlindBeanExtension.beforeEach(org.junit.jupiter.api.extension.ExtensionContext)">
      <reason>JUnit 5 BeforeEachCallback contract — signature is fixed by the framework SPI</reason>
    </element>
  </contract_signatures>

<rule>You may refactor the internal logic of elements listed in <contract_signatures>, but you MUST NOT change their public signatures: method names, parameter types, parameter order, return types, or checked exceptions.</rule>
  <test_driven_requirements>
    <element path="se.deversity.blindbean.context.BlindContext">
      <coverage_goal>90</coverage_goal>
      <frameworks>JUNIT_5</frameworks>
      <test_location>src/test/java/se.deversity.blindbean/context</test_location>
    </element>
    <element path="se.deversity.blindbean.context.BlindRotation">
      <coverage_goal>90</coverage_goal>
      <frameworks>JUNIT_5</frameworks>
      <test_location>src/test/java/se.deversity.blindbean/context</test_location>
    </element>
    <element path="se.deversity.blindbean.fhe.FheContext">
      <coverage_goal>90</coverage_goal>
      <frameworks>JUNIT_5</frameworks>
      <test_location>src/test/java/se.deversity.blindbean/fhe</test_location>
    </element>
    <element path="se.deversity.blindbean.junit.BlindBeanExtension">
      <coverage_goal>90</coverage_goal>
      <frameworks>JUNIT_5</frameworks>
      <test_location>src/test/java/se.deversity.blindbean/junit</test_location>
    </element>
  </test_driven_requirements>

<rule>For any element listed in <test_driven_requirements>, you MUST provide both the implementation change AND the corresponding test code update in a single response. Changes without tests are incomplete and must not be proposed.</rule>
  <thread_safe_elements>
    <element path="se.deversity.blindbean.async.BlindAsync">
      <strategy>OTHER</strategy>
      <note>Executor + semaphore held as one immutable State behind a single volatile (DCL lazy init); CPU-bound semaphore serializes FHE tasks across virtual threads; shutdown races resolved by re-submitting under the init monitor, which shutdown() must also acquire</note>
    </element>
    <element path="se.deversity.blindbean.context.BlindContext">
      <strategy>THREAD_LOCAL</strategy>
      <note>Paillier and FHE state isolated in ThreadLocal fields; snapshot()/restore() required to propagate across virtual-thread boundaries</note>
    </element>
    <element path="se.deversity.blindbean.context.BlindRotation">
      <strategy>OTHER</strategy>
      <note>rotate() is concurrency-safe: PaillierMath is effectively immutable with a thread-safe SecureRandom, and each FheContext serializes its own native calls on nativeLock. The counter is an AtomicLong; commit()/close() are guarded by the session monitor and flip volatile flags that rotate() reads.</note>
    </element>
    <element path="se.deversity.blindbean.fhe.FheContext">
      <strategy>SYNCHRONIZED</strategy>
      <note>All native FFM operations are guarded by nativeLock to prevent concurrent SEAL context access</note>
    </element>
    <element path="se.deversity.blindbean.math.PaillierVectorized">
      <strategy>IMMUTABLE</strategy>
      <note>Stateless utility class — SPECIES is a compile-time constant; no instance state</note>
    </element>
  </thread_safe_elements>

<rule>Elements listed in <thread_safe_elements> are explicitly designed to be thread-safe via the named strategy. Any modification MUST preserve the synchronization invariant and document its reasoning in the change description.</rule>
  <immutable_types>
    <type path="se.deversity.blindbean.core.Ciphertext">
      <note>Java record — hexData and scheme are final record components; do not convert to a mutable class</note>
    </type>
    <type path="se.deversity.blindbean.math.PaillierKeyPair">
      <note>All key material is computed once in the constructor and stored in final fields; never add setters, non-final fields, or post-construction mutation</note>
    </type>
  </immutable_types>

<rule>Types listed in <immutable_types> are immutable by design. Never introduce non-final fields, setters, or methods that mutate instance state.</rule>
  <observability_instrumentation>
    <element path="se.deversity.blindbean.fhe.FheContext.noiseBudget(java.lang.foreign.MemorySegment)">
      <metric>fhe.noise_budget</metric>
      <note>Noise budget drives correctness alerts — dashboards fire when budget drops below safe threshold; do not remove or rename this method</note>
    </element>
  </observability_instrumentation>

<rule>Elements listed in <observability_instrumentation> publish metrics, traces, or log statements that downstream dashboards and alerts depend on. Never remove or rename instrumentation without flagging the corresponding dashboard update.</rule>
  <test_isolation_elements>
    <element path="se.deversity.blindbean.async.BlindAsync">
      <isolation>strict</isolation>
    </element>
  </test_isolation_elements>

<rule>For elements in <test_isolation_elements>, all generated or modified tests MUST run in complete isolation (no shared state, external resource conflicts, or order dependencies).</rule>
  <architecture_elements>
    <element path="se.deversity.blindbean.math.BlindMath">
      <belongs_to>math-layer</belongs_to>
      <cannot_reference>se.deversity.blindbean.fhe.FheNativeBridge</cannot_reference>
    </element>
  </architecture_elements>

<rule>Respect layered architectural constraints in <architecture_elements>. Boundary crossing references are strictly prohibited.</rule>
  <public_api_elements>
    <element path="se.deversity.blindbean.context.BlindContext">
      <api>public</api>
    </element>
    <element path="se.deversity.blindbean.context.BlindRotation">
      <api>public</api>
    </element>
    <element path="se.deversity.blindbean.core.Ciphertext">
      <api>public</api>
    </element>
    <element path="se.deversity.blindbean.junit.BlindBeanExtension">
      <api>public</api>
      <reason>Consumers reference this extension directly via @ExtendWith and inherit it through @BlindBeanTest; renaming or changing its callbacks breaks every downstream test suite</reason>
    </element>
    <element path="se.deversity.blindbean.junit.BlindBeanTest">
      <api>public</api>
      <reason>Attribute names (scheme, polyModulusDegree, ckksScale) and their defaults are written into consumer test classes; renaming or removing one silently changes which context those suites boot</reason>
    </element>
    <element path="se.deversity.blindbean.math.BlindMath">
      <api>public</api>
    </element>
  </public_api_elements>

<rule>Elements in <public_api_elements> expose public API. Preserve public signature, Javadoc, and backwards compatibility without exceptions.</rule>
  <strict_exceptions_elements>
    <element path="se.deversity.blindbean.fhe.FheCiphertextNative">
      <exceptions>strict</exceptions>
    </element>
    <element path="se.deversity.blindbean.fhe.FheContext.initNative(java.util.function.Supplier&lt;java.lang.foreign.MemorySegment&gt;)">
      <exceptions>strict</exceptions>
      <reason>Only linkage errors may be translated here; a genuine SEAL failure must not be disguised as a missing-library problem</reason>
    </element>
    <element path="se.deversity.blindbean.math.PaillierMath">
      <exceptions>strict</exceptions>
    </element>
  </strict_exceptions_elements>

<rule>Catching or throwing generic Exception/Throwable is strictly prohibited in <strict_exceptions_elements>. Precise or custom exceptions required.</rule>
  <strict_types_elements>
    <element path="se.deversity.blindbean.math.BlindMath">
      <types>strict</types>
    </element>
  </strict_types_elements>

<rule>Loose typing (Object, Map<String, Object>, raw types) is strictly prohibited in <strict_types_elements>. Enforce type safety.</rule>
  <internationalized_elements>
    <element path="se.deversity.blindbean.processor.HomomorphicProcessor">
      <i18n>required</i18n>
    </element>
  </internationalized_elements>

<rule>Do not hardcode user-facing strings in <internationalized_elements>. Resolve all text via localization resource/message bundles.</rule>
  <strict_classpath_elements>
    <element path="se.deversity.blindbean.processor.HomomorphicProcessor">
      <classpath>strict</classpath>
    </element>
  </strict_classpath_elements>

<rule>Dynamic class loading, custom classloaders, reflection hacks, or unverified external code are prohibited in <strict_classpath_elements>.</rule>
  <schema_safe_elements>
    <element path="se.deversity.blindbean.context.KeyBundle">
      <schema>safe</schema>
    </element>
    <element path="se.deversity.blindbean.core.Ciphertext">
      <schema>safe</schema>
    </element>
    <element path="se.deversity.blindbean.math.PaillierKeyPair">
      <schema>safe</schema>
    </element>
  </schema_safe_elements>

<rule>Database or contract schema / serialization safety must be preserved in <schema_safe_elements>. Do not alter structures without migration paths.</rule>
  <idempotent_elements>
    <element path="se.deversity.blindbean.context.BlindContext.clear()">
      <idempotent>true</idempotent>
      <reason>ThreadLocal.remove() and FheContext.close() are both safe to call when no state is present</reason>
    </element>
    <element path="se.deversity.blindbean.context.BlindRotation.commit()">
      <idempotent>true</idempotent>
      <reason>The second call observes committed == true and returns; installing the same keys twice must not be an error, and the source is retired once</reason>
    </element>
    <element path="se.deversity.blindbean.context.BlindRotation.close()">
      <idempotent>true</idempotent>
      <reason>Guarded by the closed flag; repeated close() is a no-op and never disturbs the installed context or double-frees a native context</reason>
    </element>
    <element path="se.deversity.blindbean.fhe.FheCiphertextNative.close()">
      <idempotent>true</idempotent>
      <reason>Guarded by freed flag; calling close() on an already-freed handle is a no-op</reason>
    </element>
    <element path="se.deversity.blindbean.fhe.FheContext.close()">
      <idempotent>true</idempotent>
      <reason>Guarded by closed flag; subsequent calls after first close() are no-ops</reason>
    </element>
    <element path="se.deversity.blindbean.junit.BlindBeanExtension.afterEach(org.junit.jupiter.api.extension.ExtensionContext)">
      <idempotent>true</idempotent>
      <reason>Cleanup must tolerate a failed/partial beforeEach and repeated invocation — BlindContext.clear() is itself idempotent; never make teardown conditional on setup having succeeded, or a failing test would leak keys and native handles into the next one</reason>
    </element>
  </idempotent_elements>

<rule>Operations listed in <idempotent_elements> must remain idempotent. Never introduce side effects that cause repeated invocations to produce different results.</rule>
  <feature_flag_elements>
    <element path="se.deversity.blindbean.async.BlindAsync">
      <flag>blindbean.apt.async</flag>
      <default_value>false</default_value>
    </element>
    <element path="se.deversity.blindbean.processor.HomomorphicProcessor.generateBlindWrapper(java.lang.String,java.lang.String,javax.lang.model.element.TypeElement,java.util.List&lt;se.deversity.blindbean.processor.HomomorphicProcessor.FieldModel&gt;,java.util.List&lt;se.deversity.blindbean.processor.HomomorphicProcessor.NestedModel&gt;)">
      <flag>blindbean.apt.async</flag>
      <default_value>false</default_value>
    </element>
  </feature_flag_elements>

<rule>Elements listed in <feature_flag_elements> are gated by a feature flag. Always preserve the flag check — never assume the flag is always active.</rule>
  <security_elements>
    <element path="se.deversity.blindbean.context.BlindContext">
      <aspect>key-management</aspect>
    </element>
    <element path="se.deversity.blindbean.context.BlindContext.exportKeys(java.lang.String)">
      <aspect>key-serialization</aspect>
    </element>
    <element path="se.deversity.blindbean.context.BlindContext.loadKeys(java.lang.String)">
      <aspect>key-deserialization</aspect>
    </element>
    <element path="se.deversity.blindbean.context.BlindRotation">
      <aspect>key-rotation</aspect>
    </element>
    <element path="se.deversity.blindbean.fhe.FheContext">
      <aspect>fhe-encryption</aspect>
    </element>
    <element path="se.deversity.blindbean.math.PaillierKeyPair">
      <aspect>key-generation</aspect>
    </element>
    <element path="se.deversity.blindbean.math.PaillierMath">
      <aspect>paillier-encryption</aspect>
    </element>
  </security_elements>

<rule>Elements listed in <security_elements> are security-critical. Never weaken their security properties. Every proposed change must be explicitly reviewed for security impact.</rule>
  <access_limitations>
    <file path="se.deversity.blindbean.context.KeyBundle">
      <allowed_callers>se.deversity.blindbean.context.BlindContext</allowed_callers>
    </file>
  </access_limitations>

<rule>Do not invoke elements in <access_limitations> from outside their specified allowed caller packages or classes.</rule>
  <memory_budget_elements>
    <file path="se.deversity.blindbean.math.PaillierVectorized.batchAdd(long[],long[],long[],long)">
      <allocation_policy>NO_AUTOBOXING</allocation_policy>
    </file>
  </memory_budget_elements>

<rule>Avoid runtime heap object allocations, autoboxing, or dynamic overhead within classes/methods in <memory_budget_elements>.</rule>
  <pure_functions>
    <file path="se.deversity.blindbean.math.PaillierVectorized.batchAddBigInteger(java.math.BigInteger[],java.math.BigInteger[],java.math.BigInteger)">
      <policy>Pure function: no side effects, deterministic.</policy>
    </file>
  </pure_functions>

<rule>Methods in <pure_functions> must remain mathematically pure. Side effects, mutations of class/static state, or blocking operations are strictly forbidden.</rule>
  <domain_model_elements>
    <file path="se.deversity.blindbean.core.Ciphertext">
      <domain_model_boundary>Pure Domain Model</domain_model_boundary>
      <allowed_imports>se.deversity.blindbean.annotations.Scheme</allowed_imports>
    </file>
  </domain_model_elements>

<rule>Classes in <domain_model_elements> are pure domain models. Do not import or reference database or web framework dependencies (Spring, Hibernate, JPA, Jackson).</rule>
  <sanitization_elements>
    <file path="se.deversity.blindbean.context.BlindContext.exportKeys(java.lang.String)#filePath">
      <sanitization_types>PATH_TRAVERSAL</sanitization_types>
    </file>
    <file path="se.deversity.blindbean.context.BlindContext.loadKeys(java.lang.String)#filePath">
      <sanitization_types>PATH_TRAVERSAL</sanitization_types>
    </file>
  </sanitization_elements>

<rule>Strict input sanitization is mandatory for elements in <sanitization_elements>. Raw input must pass through approved filters before hitting queries or renderers.</rule>
  <secure_logging_elements>
    <file path="se.deversity.blindbean.context.KeyBundle.paillierKeyPair">
      <logging_policy>OMIT</logging_policy>
    </file>
    <file path="se.deversity.blindbean.context.KeyBundle.nativeFhePayload">
      <logging_policy>OMIT</logging_policy>
    </file>
    <file path="se.deversity.blindbean.math.PaillierKeyPair.lambda">
      <logging_policy>OMIT</logging_policy>
    </file>
    <file path="se.deversity.blindbean.math.PaillierKeyPair.mu">
      <logging_policy>OMIT</logging_policy>
    </file>
  </secure_logging_elements>

<rule>Sensitive variables in <secure_logging_elements> must never be printed or logged in raw form. Enforce secure masking or hashing.</rule>
  <explain_elements>
    <file path="se.deversity.blindbean.math.PaillierMath">
      <explanation_required>HIGH</explanation_required>
    </file>
    <file path="se.deversity.blindbean.math.PaillierVectorized.batchAdd(long[],long[],long[],long)">
      <explanation_required>HIGH</explanation_required>
    </file>
  </explain_elements>

<rule>Any modification to elements in <explain_elements> requires an explicit, structured Chain-of-Thought markdown description of changes and complexity analysis.</rule>
</project_guardrails>

<rule>Never propose edits to files listed in <locked_files>.</rule>
<!-- VIBETAGS-END -->
