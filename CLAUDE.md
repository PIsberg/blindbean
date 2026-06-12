# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

BlindBean is a Java 26 library that hides Homomorphic Encryption behind annotations. Developers mark fields with `@Homomorphic` and operate on encrypted values through generated wrapper proxies. Paillier is implemented in pure Java (Vector API); BFV/CKKS bridge to Microsoft SEAL 4.1 via a C++ DLL over Project Panama FFM (no JNI).

## Build & Test

Requires **JDK 26-ea** with `--enable-preview` and `--add-modules jdk.incubator.vector`. The native DLL must be built before the Java tests that exercise FHE will pass.

```bash
# 1. Build native SEAL bridge (one-time / when src/main/native changes)
cmake -S src/main/native -B build-native \
    -DCMAKE_TOOLCHAIN_FILE=<vcpkg-root>/scripts/buildsystems/vcpkg.cmake \
    -DVCPKG_TARGET_TRIPLET=x64-windows-static
cmake --build build-native --config Release

# 2. Build + install Java library
./mvnw clean install -B -Dblindbean.native.path=build-native

# 3. Run tests
./mvnw clean test -Dblindbean.native.path=build-native

# Single test
./mvnw test -Dtest=FheContextTest -Dblindbean.native.path=build-native
./mvnw test -Dtest=FheContextTest#encryptsAndDecryptsLong -Dblindbean.native.path=build-native

# JMH benchmarks
./mvnw clean verify
java --enable-preview --add-modules jdk.incubator.vector -jar target/benchmarks.jar
```

On Windows use `mvnw.cmd` and `-Dblindbean.native.path=build-native/Release` (MSVC puts artifacts under the config subdir; non-Windows builds do not).

The `blindbean-example` module is a separate Maven project demonstrating consumer usage of `@Homomorphic` / `@BlindEntity` and the generated wrappers — build the main library with `install` first so the example can resolve it.

## Architecture (three layers)

1. **Developer layer — `com.blindbean.annotations` + `com.blindbean.processor.HomomorphicProcessor`.** An annotation processor (registered via AutoService) runs at compile time, reads `@BlindEntity` / `@Homomorphic` classes, resolves the `type()` TypeMirror (e.g. `String.class`, `long[].class`, `boolean.class`), and generates `<Entity>BlindWrapper` source files. Proxies are **source-generated, not reflective** — do not add runtime reflection or bytecode weaving. The processor must also enforce algebraic boundaries: math operations (`add*`/`multiply*`) are omitted for String / boolean fields because they would corrupt the encoded value.

2. **Java FFM layer — `com.blindbean.fhe` + `com.blindbean.math` + `com.blindbean.context`.** `FheContext` owns a native `BlindBeanContext*` as an opaque `MemorySegment` and is `AutoCloseable`; callers must use try-with-resources or leak native heap. `FheNativeBridge` resolves all ~15 native symbols **once at class-load** via `SymbolLookup.loaderLookup()` into `MethodHandle` statics (`MH_ADD`, `MH_MULTIPLY`, etc.) — any new native call must follow the same pattern. `FheCiphertextNative` wraps individual ciphertext handles and provides `toBlindCiphertext()` / `fromBlindCiphertext()` for serialization across the FFM boundary. `BlindMath` is the dispatcher that routes operations to either the pure-Java Paillier (`com.blindbean.math`, Vector API / SIMD) path or the native FHE path via `BlindContext`.

3. **Native layer — `src/main/native/blindbean_fhe.{h,cpp}`.** Single DLL (`blindbean_fhe.dll`) built statically against SEAL + CRT (`x64-windows-static` triplet) so deployment needs no extra runtime. All exported symbols use `extern "C"` and `__declspec(dllexport)` on Windows. State lives in a `BlindBeanContext` struct on the C++ heap; Java never sees SEAL types directly. BFV auto-relinearizes after multiply; CKKS auto-relinearizes and rescales. Parameters target 128-bit security per the HomomorphicEncryption.org standard — **do not lower poly modulus degree below 8192 or weaken coeff modulus without an explicit request**.

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

GitHub Actions runs three jobs: a fast Java-only gate on Linux+macOS (annotation processor + core regressions), a native build matrix on Linux/macOS/Windows publishing the shared library as an artifact, and the full Maven test suite on Windows against the published `blindbean_fhe.dll`. Changes touching `src/main/native/**` require the native matrix to stay green before the Windows test job can consume the artifact.

## Further reading

`docs/ARCHITECTURE.md` has PlantUML class/sequence diagrams of the FHE multiply flow and the full FFM bridge parameter table. `README.md` has the annotation-level quickstart and scheme parameter choices.

<!-- VIBETAGS-START -->
<!-- # Generated by VibeTags | https://github.com/PIsberg/vibetags -->
<project_guardrails>
  <locked_files>
    <file path="com.blindbean.context.KeyBundle.serialVersionUID">
      <reason>Serialization UID — altering this invalidates all persisted key bundles and breaks key import/export across versions</reason>
    </file>
    <file path="com.blindbean.fhe.FheNativeBridge">
      <reason>Direct Memory FFM JNI mapping. Avoid breaking SEAL bridge architecture.</reason>
    </file>
    <file path="com.blindbean.math.PaillierKeyPair.serialVersionUID">
      <reason>Serialization UID — changing this breaks deserialization of persisted KeyBundle files</reason>
    </file>
  </locked_files>
  <contextual_instructions>
    <file path="com.blindbean.processor.HomomorphicProcessor">
      <focus>Strictly maintain high-performance AST compilation speed</focus>
      <avoids>Heavy internal object allocations</avoids>
    </file>
  </contextual_instructions>

  <audit_requirements>
    <file path="com.blindbean.async.BlindAsync">
      <vulnerability_check>Thread Safety</vulnerability_check>
      <vulnerability_check>Resource Leaks</vulnerability_check>
      <vulnerability_check>Shutdown race conditions</vulnerability_check>
    </file>
    <file path="com.blindbean.context.BlindContext">
      <vulnerability_check>Resource Leaks</vulnerability_check>
      <vulnerability_check>Thread Safety</vulnerability_check>
      <vulnerability_check>Context Closure failures</vulnerability_check>
    </file>
    <file path="com.blindbean.fhe.FheCiphertextNative">
      <vulnerability_check>Resource Leaks</vulnerability_check>
      <vulnerability_check>Memory Segment lifecycle</vulnerability_check>
      <vulnerability_check>Double-free</vulnerability_check>
    </file>
  </audit_requirements>

<rule>
  If you are asked to modify any file listed in <audit_requirements>, you must first silently analyze your proposed code for the listed <vulnerability_check> items. If your code introduces these vulnerabilities, you must rewrite it before displaying it to the user.
</rule>
  <ignored_elements>
    <file path="com.blindbean.async.BlindAsync.INIT_LOCK"/>
    <file path="com.blindbean.processor.HomomorphicProcessor.isIntegral(java.lang.String)"/>
    <file path="com.blindbean.processor.HomomorphicProcessor.isFloatingPoint(java.lang.String)"/>
    <file path="com.blindbean.processor.HomomorphicProcessor.getPrimitiveType(java.lang.String)"/>
    <file path="com.blindbean.processor.HomomorphicProcessor.getBoxedType(java.lang.String)"/>
  </ignored_elements>

<rule>Never reference or suggest changes to any element listed in <ignored_elements>. Treat these as if they do not exist.</rule>
  <pii_guardrails>
    <element path="com.blindbean.context.KeyBundle">
      <reason>Contains serialized Paillier private key material and SEAL key bytes — never log, transmit in plaintext, or expose field values in suggestions or test fixtures</reason>
    </element>
    <element path="com.blindbean.math.PaillierKeyPair">
      <reason>Contains RSA-family private key components (lambda, mu) — never log values, include in test fixtures, or expose in suggestions</reason>
    </element>
  </pii_guardrails>

<rule>
  Never include runtime values of elements listed in <pii_guardrails> in logs, console output, external API calls, test fixtures, mock data, or code suggestions. Treat their values as strictly confidential.
</rule>
  <core_elements>
    <element path="com.blindbean.context.BlindContext">
      <sensitivity>High</sensitivity>
      <note>Well-tested core functionality. Make changes with extreme caution.</note>
    </element>
    <element path="com.blindbean.fhe.FheContext">
      <sensitivity>High</sensitivity>
      <note>Well-tested core functionality. Make changes with extreme caution.</note>
    </element>
    <element path="com.blindbean.fhe.FheNativeBridge">
      <sensitivity>High</sensitivity>
      <note>Well-tested core functionality. Make changes with extreme caution.</note>
    </element>
  </core_elements>

<rule>Elements listed in <core_elements> are well-tested core components. Make changes with extreme caution and verify comprehensive test coverage before proposing modifications.</rule>
  <performance_constraints>
    <element path="com.blindbean.fhe.FheContext.encryptLongArray(long[])">
      <constraint>Strict time/space complexity constraints apply. Suboptimal complexity is unacceptable.</constraint>
    </element>
    <element path="com.blindbean.fhe.FheContext.multiply(java.lang.foreign.MemorySegment,java.lang.foreign.MemorySegment)">
      <constraint>Strict time/space complexity constraints apply. Suboptimal complexity is unacceptable.</constraint>
    </element>
    <element path="com.blindbean.math.PaillierMath">
      <constraint>Encryption/decryption are modPow-heavy over large BigIntegers — never introduce extra copies, unnecessary allocations, or redundant modular reductions on the hot path</constraint>
    </element>
    <element path="com.blindbean.math.PaillierVectorized">
      <constraint>Strict time/space complexity constraints apply. Suboptimal complexity is unacceptable.</constraint>
    </element>
    <element path="com.blindbean.math.PaillierVectorized.batchAddBigInteger(java.math.BigInteger[],java.math.BigInteger[],java.math.BigInteger)">
      <constraint>Strict time/space complexity constraints apply. Suboptimal complexity is unacceptable.</constraint>
    </element>
  </performance_constraints>

<rule>Elements listed in <performance_constraints> are on a hot path. Never introduce O(n²) or worse complexity. Always reason about time and space complexity before suggesting changes.</rule>
  <contract_signatures>
    <element path="com.blindbean.fhe.FheCiphertextNative">
      <reason>Serialization format and handle lifecycle are part of the public FFM contract; do not change method signatures</reason>
    </element>
    <element path="com.blindbean.fhe.FheContext">
      <reason>Public FHE API consumed by generated BlindWrapper classes; any signature change requires processor regeneration and a major version bump</reason>
    </element>
  </contract_signatures>

<rule>You may refactor the internal logic of elements listed in <contract_signatures>, but you MUST NOT change their public signatures: method names, parameter types, parameter order, return types, or checked exceptions.</rule>
  <test_driven_requirements>
    <element path="com.blindbean.context.BlindContext">
      <coverage_goal>90</coverage_goal>
      <frameworks>JUNIT_5</frameworks>
      <test_location>src/test/java/com/blindbean/context</test_location>
    </element>
    <element path="com.blindbean.fhe.FheContext">
      <coverage_goal>90</coverage_goal>
      <frameworks>JUNIT_5</frameworks>
      <test_location>src/test/java/com/blindbean/fhe</test_location>
    </element>
  </test_driven_requirements>

<rule>For any element listed in <test_driven_requirements>, you MUST provide both the implementation change AND the corresponding test code update in a single response. Changes without tests are incomplete and must not be proposed.</rule>
  <thread_safe_elements>
    <element path="com.blindbean.async.BlindAsync">
      <strategy>OTHER</strategy>
      <note>Double-checked locking for lazy executor init; CPU-bound semaphore serializes FHE tasks across virtual threads; shutdown races handled with retry loop</note>
    </element>
    <element path="com.blindbean.context.BlindContext">
      <strategy>THREAD_LOCAL</strategy>
      <note>Paillier and FHE state isolated in ThreadLocal fields; snapshot()/restore() required to propagate across virtual-thread boundaries</note>
    </element>
    <element path="com.blindbean.fhe.FheContext">
      <strategy>SYNCHRONIZED</strategy>
      <note>All native FFM operations are guarded by nativeLock to prevent concurrent SEAL context access</note>
    </element>
    <element path="com.blindbean.math.PaillierVectorized">
      <strategy>IMMUTABLE</strategy>
      <note>Stateless utility class — SPECIES is a compile-time constant; no instance state</note>
    </element>
  </thread_safe_elements>

<rule>Elements listed in <thread_safe_elements> are explicitly designed to be thread-safe via the named strategy. Any modification MUST preserve the synchronization invariant and document its reasoning in the change description.</rule>
  <immutable_types>
    <type path="com.blindbean.core.Ciphertext">
      <note>Java record — hexData and scheme are final record components; do not convert to a mutable class</note>
    </type>
    <type path="com.blindbean.math.PaillierKeyPair">
      <note>All key material is computed once in the constructor and stored in final fields; never add setters, non-final fields, or post-construction mutation</note>
    </type>
  </immutable_types>

<rule>Types listed in <immutable_types> are immutable by design. Never introduce non-final fields, setters, or methods that mutate instance state.</rule>
  <observability_instrumentation>
    <element path="com.blindbean.fhe.FheContext.noiseBudget(java.lang.foreign.MemorySegment)">
      <metric>fhe.noise_budget</metric>
      <note>Noise budget drives correctness alerts — dashboards fire when budget drops below safe threshold; do not remove or rename this method</note>
    </element>
  </observability_instrumentation>

<rule>Elements listed in <observability_instrumentation> publish metrics, traces, or log statements that downstream dashboards and alerts depend on. Never remove or rename instrumentation without flagging the corresponding dashboard update.</rule>
  <test_isolation_elements>
    <element path="com.blindbean.async.BlindAsync">
      <isolation>strict</isolation>
    </element>
  </test_isolation_elements>

<rule>For elements in <test_isolation_elements>, all generated or modified tests MUST run in complete isolation (no shared state, external resource conflicts, or order dependencies).</rule>
  <architecture_elements>
    <element path="com.blindbean.math.BlindMath">
      <belongs_to>math-layer</belongs_to>
      <cannot_reference>com.blindbean.fhe.FheNativeBridge</cannot_reference>
    </element>
  </architecture_elements>

<rule>Respect layered architectural constraints in <architecture_elements>. Boundary crossing references are strictly prohibited.</rule>
  <public_api_elements>
    <element path="com.blindbean.context.BlindContext">
      <api>public</api>
    </element>
    <element path="com.blindbean.core.Ciphertext">
      <api>public</api>
    </element>
    <element path="com.blindbean.math.BlindMath">
      <api>public</api>
    </element>
  </public_api_elements>

<rule>Elements in <public_api_elements> expose public API. Preserve public signature, Javadoc, and backwards compatibility without exceptions.</rule>
  <strict_exceptions_elements>
    <element path="com.blindbean.fhe.FheCiphertextNative">
      <exceptions>strict</exceptions>
    </element>
    <element path="com.blindbean.math.PaillierMath">
      <exceptions>strict</exceptions>
    </element>
  </strict_exceptions_elements>

<rule>Catching or throwing generic Exception/Throwable is strictly prohibited in <strict_exceptions_elements>. Precise or custom exceptions required.</rule>
  <strict_types_elements>
    <element path="com.blindbean.math.BlindMath">
      <types>strict</types>
    </element>
  </strict_types_elements>

<rule>Loose typing (Object, Map<String, Object>, raw types) is strictly prohibited in <strict_types_elements>. Enforce type safety.</rule>
  <internationalized_elements>
    <element path="com.blindbean.processor.HomomorphicProcessor">
      <i18n>required</i18n>
    </element>
  </internationalized_elements>

<rule>Do not hardcode user-facing strings in <internationalized_elements>. Resolve all text via localization resource/message bundles.</rule>
  <strict_classpath_elements>
    <element path="com.blindbean.processor.HomomorphicProcessor">
      <classpath>strict</classpath>
    </element>
  </strict_classpath_elements>

<rule>Dynamic class loading, custom classloaders, reflection hacks, or unverified external code are prohibited in <strict_classpath_elements>.</rule>
  <schema_safe_elements>
    <element path="com.blindbean.context.KeyBundle">
      <schema>safe</schema>
    </element>
    <element path="com.blindbean.core.Ciphertext">
      <schema>safe</schema>
    </element>
    <element path="com.blindbean.math.PaillierKeyPair">
      <schema>safe</schema>
    </element>
  </schema_safe_elements>

<rule>Database or contract schema / serialization safety must be preserved in <schema_safe_elements>. Do not alter structures without migration paths.</rule>
  <idempotent_elements>
    <element path="com.blindbean.context.BlindContext.clear()">
      <idempotent>true</idempotent>
      <reason>ThreadLocal.remove() and FheContext.close() are both safe to call when no state is present</reason>
    </element>
    <element path="com.blindbean.fhe.FheCiphertextNative.close()">
      <idempotent>true</idempotent>
      <reason>Guarded by freed flag; calling close() on an already-freed handle is a no-op</reason>
    </element>
    <element path="com.blindbean.fhe.FheContext.close()">
      <idempotent>true</idempotent>
      <reason>Guarded by closed flag; subsequent calls after first close() are no-ops</reason>
    </element>
  </idempotent_elements>

<rule>Operations listed in <idempotent_elements> must remain idempotent. Never introduce side effects that cause repeated invocations to produce different results.</rule>
  <feature_flag_elements>
    <element path="com.blindbean.async.BlindAsync">
      <flag>blindbean.apt.async</flag>
      <default_value>false</default_value>
    </element>
    <element path="com.blindbean.processor.HomomorphicProcessor.generateBlindWrapper(java.lang.String,java.lang.String,javax.lang.model.element.TypeElement,java.util.List<com.blindbean.processor.HomomorphicProcessor.FieldModel>)">
      <flag>blindbean.apt.async</flag>
      <default_value>false</default_value>
    </element>
  </feature_flag_elements>

<rule>Elements listed in <feature_flag_elements> are gated by a feature flag. Always preserve the flag check — never assume the flag is always active.</rule>
  <security_elements>
    <element path="com.blindbean.context.BlindContext">
      <aspect>key-management</aspect>
    </element>
    <element path="com.blindbean.context.BlindContext.exportKeys(java.lang.String)">
      <aspect>key-serialization</aspect>
    </element>
    <element path="com.blindbean.context.BlindContext.loadKeys(java.lang.String)">
      <aspect>key-deserialization</aspect>
    </element>
    <element path="com.blindbean.fhe.FheContext">
      <aspect>fhe-encryption</aspect>
    </element>
    <element path="com.blindbean.math.PaillierKeyPair">
      <aspect>key-generation</aspect>
    </element>
    <element path="com.blindbean.math.PaillierMath">
      <aspect>paillier-encryption</aspect>
    </element>
  </security_elements>

<rule>Elements listed in <security_elements> are security-critical. Never weaken their security properties. Every proposed change must be explicitly reviewed for security impact.</rule>
</project_guardrails>

<rule>Never propose edits to files listed in <locked_files>.</rule>
<!-- VIBETAGS-END -->
