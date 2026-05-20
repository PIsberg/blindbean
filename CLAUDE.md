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
<!-- # Generated by VibeTags 0.9.7 | https://github.com/PIsberg/vibetags -->
<project_guardrails>
  <locked_files>
    <file path="com.blindbean.fhe.FheNativeBridge">
      <reason>Direct Memory FFM JNI mapping. Avoid breaking SEAL bridge architecture.</reason>
    </file>
    <field path="com.blindbean.math.PaillierKeyPair#serialVersionUID">
      <reason>Serialization UID — changing this breaks deserialization of persisted KeyBundle files.</reason>
    </field>
    <field path="com.blindbean.context.KeyBundle#serialVersionUID">
      <reason>Serialization UID — altering this invalidates all persisted key bundles and breaks key import/export across versions.</reason>
    </field>
  </locked_files>

  <contextual_instructions>
    <file path="com.blindbean.processor.HomomorphicProcessor">
      <focus>Strictly maintain high-performance AST compilation speed</focus>
      <avoids>Heavy internal object allocations</avoids>
      <strict_classpath>true</strict_classpath>
      <internationalized>true</internationalized>
      <note>Never introduce Class.forName(), reflection, or dynamic class loading. All user-facing compiler messages must be externalizable — do not hardcode English strings directly in printMessage() calls.</note>
    </file>
    <file path="com.blindbean.math.BlindMath">
      <strict_types>true</strict_types>
      <note>Scheme dispatch is the single source of truth — never coerce or cast across Scheme variants; always use exhaustive switch expressions.</note>
    </file>
    <file path="com.blindbean.math.PaillierMath">
      <strict_exceptions>true</strict_exceptions>
      <note>Throw specific, typed exceptions (IllegalArgumentException with scheme info, FheException with error codes). Never swallow or widen exceptions on the crypto path.</note>
    </file>
    <file path="com.blindbean.fhe.FheCiphertextNative">
      <strict_exceptions>true</strict_exceptions>
      <note>Every FheException must carry the error code from the native return value. Never use bare RuntimeException or generic catch-and-rethrow without preserving the original cause.</note>
    </file>
  </contextual_instructions>

  <audit_requirements>
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
    <file path="com.blindbean.async.BlindAsync">
      <vulnerability_check>Thread Safety</vulnerability_check>
      <vulnerability_check>Resource Leaks</vulnerability_check>
      <vulnerability_check>Shutdown race conditions</vulnerability_check>
    </file>
  </audit_requirements>

<rule>
  If you are asked to modify any file listed in <audit_requirements>, you must first silently analyze your proposed code for the listed <vulnerability_check> items. If your code introduces these vulnerabilities, you must rewrite it before displaying it to the user.
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
    <element path="com.blindbean.math.PaillierVectorized">
      <constraint>Strict time/space complexity constraints apply. Suboptimal complexity is unacceptable.</constraint>
    </element>
    <element path="com.blindbean.math.PaillierMath">
      <constraint>Encryption and decryption involve modPow over large BigIntegers — never introduce extra allocations or copy operations on the hot path.</constraint>
    </element>
  </performance_constraints>

<rule>Elements listed in <performance_constraints> are on a hot path. Never introduce O(n²) or worse complexity. Always reason about time and space complexity before suggesting changes.</rule>

  <contract_signatures>
    <element path="com.blindbean.fhe.FheContext">
      <reason>Public FHE API consumed by generated BlindWrapper classes; any signature change requires processor regeneration and a major version bump.</reason>
    </element>
    <element path="com.blindbean.fhe.FheCiphertextNative">
      <reason>Serialization format and handle lifecycle are part of the public FFM contract; do not change method signatures.</reason>
    </element>
  </contract_signatures>

<rule>Elements listed in <contract_signatures> have frozen public method signatures. Do not change method names, parameter types, parameter order, return types, or checked exceptions. Internal logic may be modified freely.</rule>

  <thread_safety>
    <element path="com.blindbean.context.BlindContext" strategy="THREAD_LOCAL">
      <note>Paillier and FHE state isolated in ThreadLocal fields; snapshot()/restore() required to propagate across virtual-thread boundaries.</note>
    </element>
    <element path="com.blindbean.fhe.FheContext" strategy="SYNCHRONIZED">
      <note>All native FFM operations are guarded by nativeLock to prevent concurrent SEAL context access.</note>
    </element>
    <element path="com.blindbean.async.BlindAsync" strategy="OTHER">
      <note>Double-checked locking for lazy executor init; CPU-bound semaphore serializes FHE tasks across virtual threads; shutdown races handled with retry loop.</note>
    </element>
    <element path="com.blindbean.math.PaillierVectorized" strategy="IMMUTABLE">
      <note>Stateless utility class — SPECIES is a compile-time constant; no instance state.</note>
    </element>
  </thread_safety>

<rule>Elements listed in <thread_safety> have documented concurrency strategies that must be preserved. Do not remove synchronization, change locking granularity, or convert ThreadLocal patterns to shared state without explicit justification.</rule>

  <security_requirements>
    <element path="com.blindbean.context.BlindContext" aspect="key-management">
      <note>Manages the lifecycle of all cryptographic key material. Any change to init, clear, exportKeys, or loadKeys requires security review.</note>
    </element>
    <element path="com.blindbean.context.BlindContext.exportKeys(java.lang.String)" aspect="key-serialization"/>
    <element path="com.blindbean.context.BlindContext.loadKeys(java.lang.String)" aspect="key-deserialization"/>
    <element path="com.blindbean.fhe.FheContext" aspect="fhe-encryption">
      <note>Wraps SEAL encryption/decryption — any weakening of encrypt/decrypt paths or parameter validation requires security review.</note>
    </element>
    <element path="com.blindbean.math.PaillierMath" aspect="paillier-encryption"/>
    <element path="com.blindbean.math.PaillierKeyPair" aspect="key-generation"/>
  </security_requirements>

<rule>Elements listed in <security_requirements> are security-critical. Any proposed change must be reviewed for cryptographic correctness. Never weaken validation, remove null checks on native handles, or alter key derivation logic.</rule>

  <privacy_fields>
    <element path="com.blindbean.math.PaillierKeyPair">
      <reason>Contains RSA-family private key components (lambda, mu) — never log values, include in test fixtures, or expose in suggestions.</reason>
    </element>
    <element path="com.blindbean.context.KeyBundle">
      <reason>Contains serialized Paillier private key material and SEAL key bytes — never log, transmit in plaintext, or expose field values in suggestions or test fixtures.</reason>
    </element>
  </privacy_fields>

<rule>Elements listed in <privacy_fields> contain sensitive key material. Never include their runtime values in log statements, test data, generated code suggestions, or error messages.</rule>

  <immutable_types>
    <element path="com.blindbean.math.PaillierKeyPair">
      <note>All key material is computed once in the constructor and stored in final fields; never add setters, non-final fields, or post-construction mutation.</note>
    </element>
    <element path="com.blindbean.core.Ciphertext">
      <note>Java record — hexData and scheme are final record components; do not convert to a mutable class.</note>
    </element>
  </immutable_types>

<rule>Elements listed in <immutable_types> must remain immutable. Do not add non-final fields, setter methods, or any operation that mutates state after construction.</rule>

  <schema_safe>
    <element path="com.blindbean.math.PaillierKeyPair"/>
    <element path="com.blindbean.context.KeyBundle"/>
    <element path="com.blindbean.core.Ciphertext"/>
  </schema_safe>

<rule>Elements listed in <schema_safe> have stable serialization/wire formats. Never remove or rename fields, change field types, or alter the hex-encoding convention without a versioned migration strategy.</rule>

  <architecture_constraints>
    <element path="com.blindbean.math.BlindMath" layer="math-layer">
      <cannot_reference>com.blindbean.fhe.FheNativeBridge</cannot_reference>
      <note>BlindMath must only cross the FFM boundary via FheContext — never import or call FheNativeBridge directly.</note>
    </element>
  </architecture_constraints>

<rule>Elements listed in <architecture_constraints> must not reference the listed forbidden packages or classes. Enforce layer boundaries by routing through the correct abstraction.</rule>

  <public_api>
    <element path="com.blindbean.context.BlindContext"/>
    <element path="com.blindbean.math.BlindMath"/>
    <element path="com.blindbean.core.Ciphertext"/>
  </public_api>

<rule>Elements listed in <public_api> are stable library surfaces. All changes must be backward-compatible: do not remove methods, change signatures, or alter documented behavior without a major version increment.</rule>

  <feature_flags>
    <element path="com.blindbean.processor.HomomorphicProcessor.generateBlindWrapper" flag="blindbean.apt.async" default="false">
      <note>Async wrapper generation is opt-in via @BlindEntity(async=true) or -Dblindbean.apt.async=true. Never assume the flag is always active; generated code must compile and work correctly in both states.</note>
    </element>
    <element path="com.blindbean.async.BlindAsync" flag="blindbean.apt.async" default="false">
      <note>BlindAsync is the runtime for async-enabled wrappers. It must remain a no-overhead import when async is disabled.</note>
    </element>
  </feature_flags>

<rule>Elements listed in <feature_flags> are gated behind runtime or compile-time flags. Always preserve the guard condition and validate behavior for both enabled and disabled states.</rule>

  <observability>
    <element path="com.blindbean.fhe.FheContext.noiseBudget(java.lang.foreign.MemorySegment)">
      <metric>fhe.noise_budget</metric>
      <note>Noise budget monitoring is essential for FHE correctness — dashboards alert when budget drops below safe threshold. Do not remove, rename, or change the return semantics of this method.</note>
    </element>
  </observability>

<rule>Elements listed in <observability> emit metrics, traces, or log tokens that external dashboards and alerts depend on. Do not rename or remove them without updating dependent monitoring configuration.</rule>

  <test_requirements>
    <element path="com.blindbean.context.BlindContext" coverage_goal="90" framework="JUNIT_5"
             test_location="src/test/java/com/blindbean/context"/>
    <element path="com.blindbean.fhe.FheContext" coverage_goal="90" framework="JUNIT_5"
             test_location="src/test/java/com/blindbean/fhe"/>
    <element path="com.blindbean.async.BlindAsync" parallel_isolation="true">
      <note>Tests must not share mutable BlindAsync state, rely on execution order, or conflict on the internal executor. Each test must call BlindAsync.shutdown() in teardown.</note>
    </element>
  </test_requirements>

<rule>When modifying elements listed in <test_requirements>, you must include matching test changes in the same response. For parallel_isolation=true elements, generated tests must not share state or rely on ordering.</rule>

  <draft_implementations>
    <element path="com.blindbean.math.PaillierVectorized.batchAdd(long[],long[],long[],long)">
      <instructions>Replace stand-in long arithmetic with true vectorized modular reduction: implement Barrett or Montgomery reduction across SIMD lanes to handle BigInteger-scale carry propagation. Each lane must reduce mod n² correctly; see PaillierKeyPair.getN2().</instructions>
    </element>
  </draft_implementations>

<rule>Elements listed in <draft_implementations> are intentional placeholders. When asked to implement them, follow the provided instructions precisely and include unit tests covering edge cases.</rule>

  <ignored_elements>
    <element path="com.blindbean.processor.HomomorphicProcessor.isIntegral(java.lang.String)"/>
    <element path="com.blindbean.processor.HomomorphicProcessor.isFloatingPoint(java.lang.String)"/>
    <element path="com.blindbean.processor.HomomorphicProcessor.getPrimitiveType(java.lang.String)"/>
    <element path="com.blindbean.processor.HomomorphicProcessor.getBoxedType(java.lang.String)"/>
    <field path="com.blindbean.async.BlindAsync#INIT_LOCK"/>
  </ignored_elements>

<rule>Elements listed in <ignored_elements> are internal implementation details. Do not reference, suggest changes to, or include them when generating code for external callers.</rule>

  <idempotent_operations>
    <element path="com.blindbean.context.BlindContext.clear()">
      <reason>ThreadLocal.remove() and FheContext.close() are both safe to call when no state is present.</reason>
    </element>
    <element path="com.blindbean.fhe.FheContext.close()">
      <reason>Guarded by closed flag; subsequent calls after first close() are no-ops.</reason>
    </element>
    <element path="com.blindbean.fhe.FheCiphertextNative.close()">
      <reason>Guarded by freed flag; calling close() on an already-freed handle is a no-op.</reason>
    </element>
  </idempotent_operations>

<rule>Elements listed in <idempotent_operations> must tolerate repeated invocation. Never introduce state changes that make a second call fail or behave differently from a no-op.</rule>

</project_guardrails>

<rule>Never propose edits to files listed in <locked_files>.</rule>
<!-- VIBETAGS-END -->
