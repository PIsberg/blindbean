# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Project Is

**BlindBean** is a Java 26 library for transparent Homomorphic Encryption (HE). Developers annotate fields with `@Homomorphic`; BlindBean generates wrapper classes that perform arithmetic on encrypted data without ever decrypting it. Philosophy: "It feels like Hibernate. You annotate, we calculate."

## Build & Test Commands

```bash
# Build the native SEAL-backed DLL (requires CMake 3.16+, vcpkg, C++17 compiler)
cmake -S src/main/native -B build-native -DCMAKE_TOOLCHAIN_FILE=<vcpkg-root>/scripts/buildsystems/vcpkg.cmake
cmake --build build-native --config Release

# Build and install all modules (pass native DLL path)
mvn clean install -B -Dblindbean.native.path=build-native/Release

# Run tests (core library)
mvn clean test -Dblindbean.native.path=build-native/Release

# Run a single test class
mvn test -pl . -Dtest=BlindMathTest -Dblindbean.native.path=build-native/Release

# Build and test the example module
cd blindbean-example && mvn clean test -B

# Run JMH benchmarks (after build)
java -jar target/benchmarks.jar
```

The CI pipeline runs on `windows-latest` with Oracle JDK 26-ea. It builds the SEAL-backed native DLL via CMake + vcpkg, then runs the full Maven test suite.

All Maven runs require these JVM flags (already configured in `pom.xml`):
- `--enable-preview` (Java 26 preview features)
- `--add-modules jdk.incubator.vector` (Vector API)
- `--enable-native-access=ALL-UNNAMED` (Project Panama FFM)

## Architecture

BlindBean has three tiers:

### 1. Developer Layer — Annotations & Code Generation
- `@BlindEntity` marks a class managed by BlindBean
- `@Homomorphic(scheme=Scheme.PAILLIER)` marks a field to be encrypted
- `HomomorphicProcessor` (compile-time APT via Google AutoService) generates `*BlindWrapper` proxy classes at build time — no reflection, no runtime weaving
- Generated wrappers expose methods like `addFunds(Ciphertext)` that perform homomorphic operations transparently

### 2. Pure Java Layer — Paillier + Vector API
- `BlindContext`: ThreadLocal singleton; **must call `BlindContext.init()` before any crypto**
- `PaillierKeyPair`: 1024-bit key generation (Carmichael λ, modular inverse μ)
- `PaillierMath`: Paillier encrypt/decrypt/homomorphic-add via `BigInteger`
- `BlindMath`: Switch-expression dispatcher routing operations to scheme implementations (Paillier, BFV, CKKS)
- `PaillierVectorized`: Batch modular multiplication using Java 26 `jdk.incubator.vector` (SIMD)
- `Ciphertext` record: Immutable `(String hexData, Scheme scheme)` — ciphertexts live as hex strings in entity fields

### 3. Native Layer — Microsoft SEAL via Project Panama
- `FheNativeBridge`: FFM downcall handles into `blindbean_fhe.dll`, backed by **Microsoft SEAL 4.1**
- `FheContext`: AutoCloseable wrapper around native SEAL context (BFV or CKKS), enables try-with-resources
- `FheCiphertextNative`: AutoCloseable wrapper for native ciphertexts with serialize/deserialize support
- `FheException`: Dedicated exception type for native FHE errors
- Supports **BFV** (exact integer arithmetic) and **CKKS** (approximate real arithmetic)
- Zero-JNI approach uses cached `MethodHandle` downcalls resolved once at class-load time
- Native source: `src/main/native/blindbean_fhe.{h,cpp}`, built via CMake + vcpkg
- SEAL parameters use 128-bit security defaults

## Key Conventions

- **Ciphertext storage**: Encrypted values are stored as hex strings in entity fields (e.g., `String balance`), opaque to domain logic.
- **ThreadLocal lifecycle**: `BlindContext.init()` initializes Paillier; `BlindContext.initBfv()` / `BlindContext.initCkks()` initializes SEAL FHE. Tests must call these before encrypting.
- **Scheme dispatch**: New schemes are added by extending `Scheme` enum and adding a case in `BlindMath`.
- **Native DLL discovery**: `FheNativeBridge` resolves the DLL via (1) `blindbean.native.path` system property, (2) `src/main/native/` dev path, (3) `java.library.path`.
- **SEAL security parameters**: BFV defaults use `CoeffModulus::BFVDefault()` and `PlainModulus::Batching()` at 128-bit security. CKKS defaults use `CoeffModulus::Create()` with `{60, 40, 40, 60}` primes.
- **Multi-module Maven**: Root POM aggregates `blindbean-core` (library) and `blindbean-example` (end-to-end demo with `WalletTest`).
