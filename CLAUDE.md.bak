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
    <file path="com.blindbean.fhe.FheNativeBridge">
      <reason>Direct Memory FFM JNI mapping. Avoid breaking SEAL bridge architecture.</reason>
    </file>
  </locked_files>
  <contextual_instructions>
    <file path="com.blindbean.processor.HomomorphicProcessor">
      <focus>Strictly maintain high-performance AST compilation speed</focus>
      <avoids>Heavy internal object allocations</avoids>
    </file>
  </contextual_instructions>

  <audit_requirements>
    <file path="com.blindbean.context.BlindContext">
      <vulnerability_check>Resource Leaks</vulnerability_check>
      <vulnerability_check>Thread Safety</vulnerability_check>
      <vulnerability_check>Context Closure failures</vulnerability_check>
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
    <element path="encryptLongArray(long[])">
      <constraint>Strict time/space complexity constraints apply. Suboptimal complexity is unacceptable.</constraint>
    </element>
    <element path="multiply(java.lang.foreign.MemorySegment,java.lang.foreign.MemorySegment)">
      <constraint>Strict time/space complexity constraints apply. Suboptimal complexity is unacceptable.</constraint>
    </element>
    <element path="com.blindbean.math.PaillierVectorized">
      <constraint>Strict time/space complexity constraints apply. Suboptimal complexity is unacceptable.</constraint>
    </element>
  </performance_constraints>

<rule>Elements listed in <performance_constraints> are on a hot path. Never introduce O(n²) or worse complexity. Always reason about time and space complexity before suggesting changes.</rule>
</project_guardrails>

<rule>Never propose edits to files listed in <locked_files>.</rule>
<!-- VIBETAGS-END -->
