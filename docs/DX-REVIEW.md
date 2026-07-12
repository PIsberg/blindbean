# Developer Experience Review

An outside-in look at BlindBean from the perspective of a Java developer who wants to
try it, adopt it, and run it in production — with concrete, prioritized proposals.
The review covers onboarding, API ergonomics, integration, and operations; it does
not propose changes to the cryptography.

## Where BlindBean already shines

- The annotation model delivers on the pitch: `@Homomorphic` on a field, use the
  generated wrapper, done. `encryptFunds`/`decryptFunds`/`addFunds` on the wrapper is
  genuinely Hibernate-ish.
- Compile-time source generation (no reflection, no weaving) is the right call for
  auditability in a crypto library.
- The processor emits real diagnostics (errors on misuse, warnings) instead of
  failing silently.
- Algebraic guardrails — refusing to generate `add*`/`multiply*` for String/boolean
  fields — prevent an entire class of data-corruption bugs.
- try-with-resources native lifetime management and the noise-budget introspection
  hook are production-minded touches.

## The adoption funnel, ranked by where developers fall off

### 1. You cannot `mvn install` your way into trying it *(highest leverage)*

Today a curious developer must: install JDK 26-EA, install vcpkg + CMake + a C++
toolchain, build `blindbean_fhe.dll` themselves, then build the library from source.
That is a day of setup before the first `encrypt()`. Almost everyone bounces here.

**Proposals**
- Publish the jar to Maven Central (or at minimum GitHub Packages) so the Quickstart
  starts with a dependency snippet instead of a clone.
- Ship the native library inside platform-classifier jars
  (`blindbean-natives-windows-x64`, `-linux-x64`, `-macos-aarch64`) — CI already
  builds all three in the native matrix; today those artifacts die as run artifacts.
  Loader order: explicit `blindbean.native.path` → bundled resource extracted to a
  temp dir → clear error. This is the SQLite-JDBC / Netty pattern and it removes the
  entire native-build prerequisite for consumers.
- Add a devcontainer (or Codespaces badge) with JDK 26-EA preinstalled and the
  prebuilt DLL wired up, so "try BlindBean" is one click.

### 2. The JDK 26-EA + `--enable-preview` wall

Preview flags are viral: every consumer must compile *and run* with
`--enable-preview --add-modules jdk.incubator.vector --enable-native-access=…`, and
preview classfiles pin the exact JDK feature release. No platform team ships that.

**Proposals**
- Split the SIMD acceleration from the baseline: `PaillierMath` is BigInteger-based
  and needs none of the preview surface; FFM is final since JDK 22. A Java 21/25
  baseline artifact with `PaillierVectorized` in an optional accelerator module
  (loaded when the Vector API is available) would make the core adoptable by LTS
  shops today, with SIMD as opt-in for the adventurous.
- Until then: document the consumer-side flags as copy-paste Maven/Gradle snippets —
  right now a consumer discovers them by reading this repo's pom.

### 3. First-run failure quality

The DLL-not-found failure is fail-fast (good) but terse. This is the first error a
new user will ever see.

**Proposal:** make it a guided error: the paths that were searched, the system
property to set, whether a bundled native exists for this OS/arch, and a docs link.
One string, outsized first-impression payoff.

### 4. API ergonomics once running

- `FheContext` trades in raw `MemorySegment`s, with manual `freeCiphertext`. It
  works, but it exposes FFM plumbing as the public currency and makes leaks/misuse
  easy (`FheCiphertextNative` exists but the README examples don't lead with it).
  **Proposal (additive, no signature changes):** make a typed, `AutoCloseable`
  ciphertext handle the *documented* currency for the FHE path, keeping the
  `MemorySegment` overloads as the low-level tier for the processor-generated code.
- Entity fields are stringly-typed hex (`private String balance` +
  `type = long.class`). It is pragmatic for JPA columns, but nothing stops
  `setBalance("hello")`. **Proposal:** document the *why* (column-friendly), and
  offer an optional `Ciphertext`-typed field variant for non-JPA users, which the
  processor already has the type machinery to support.
- ~~Wrapper convenience: plaintext overloads~~ **Already shipped**: generated
  wrappers accept plaintext directly (BigInteger for Paillier, long/double/
  long[] for BFV/CKKS) via emitAddPlain/emitSubPlain — the README Quickstart
  now leads with it.

### 5. The integrations the pitch implies

"It feels like Hibernate" sets an expectation the repo can cash in on:

- **JPA:** a shipped `AttributeConverter` + usage recipe (entity ↔ column round-trip
  with a real `EntityManager` test).
- **Spring Boot starter:** auto-configuration that calls `BlindContext.init()` from
  `application.yml` properties (scheme, poly degree, key file), plus a health
  indicator exposing the noise budget metric that already exists.
- **Jackson module** for `Ciphertext` so encrypted DTOs serialize naturally in REST
  payloads.

Each is a small module, and each turns a demo into something a team can pilot.

### 6. Consumer testing story

Every consumer test today hand-rolls `BlindContext.init()` / `clear()` in
setup/teardown (see the example module).

**Proposal:** a `blindbean-test` artifact with a JUnit 5 extension
(`@BlindBeanTest`) that manages context lifecycle per test, plus an optional
fast-keys mode for suites where 128-bit-security keygen per test is wasted time —
clearly marked test-only.

### 7. Documentation gaps worth closing

- Publish Javadoc (gh-pages or javadoc.io once on Central) — the public API is small
  enough that browsable Javadoc is high value per hour.
- A security/limitations page: what Paillier vs BFV vs CKKS give and *don't* give
  (no encrypted comparisons/branching, CKKS approximation error, noise-budget
  exhaustion behavior, key rotation guidance for `exportKeys`/`loadKeys`).
- The README Quickstart references a fictional `repo.findById(1)`; a runnable
  single-file demo (JBang-friendly) would let people execute the Quickstart
  verbatim.
- IntelliJ note: enabling annotation processing + marking `generated-sources` — the
  classic first-hour APT friction.

## Suggested order of attack

| # | Item | Effort | Leverage |
|---|------|--------|----------|
| 1 | Publish jar + bundle prebuilt natives from the existing CI matrix | M | Removes the biggest adoption cliff |
| 2 | Guided native-load error message | S | ✅ Done in this PR |
| 3 | Plaintext convenience overloads in generated wrappers | S | ✅ Already shipped upstream |
| 4 | LTS-baseline artifact with optional SIMD accelerator module | L | Unlocks the 99% of shops on LTS |
| 5 | Spring Boot starter + JPA converter | M | Converts the pitch into pilots |
| 6 | @BlindBeanTest JUnit extension | S | ✅ Done in this PR |
| 7 | Javadoc + security/limitations page + runnable quickstart | M | Partial in this PR (security page, consumer-build + IntelliJ docs) |

Items 2, 3 and 6 are self-contained afternoon-sized changes; item 1 is mostly CI
plumbing around artifacts that already build; item 4 is the only one that touches
architecture and deserves its own design pass.
