# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Project Is

**BlindBean** is a Java 26 library for transparent Homomorphic Encryption (HE). Developers annotate fields with `@Homomorphic`; BlindBean generates wrapper classes that perform arithmetic on encrypted data without ever decrypting it. Philosophy: "It feels like Hibernate. You annotate, we calculate."

## Build & Test Commands

```bash
# Build and install all modules
mvn clean install -B

# Run tests (core library)
mvn clean test

# Run a single test class
mvn test -pl . -Dtest=BlindMathTest

# Build and test the example module
cd blindbean-example && mvn clean test -B

# Run JMH benchmarks (after build)
java -jar target/benchmarks.jar
```

The CI pipeline runs on `windows-latest` with Oracle JDK 26-ea. It also compiles the native DLL:
```bash
gcc -shared -o blindbean_fhe.dll blindbean_fhe.c
```

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
- `BlindMath`: Switch-expression dispatcher routing operations to scheme implementations
- `PaillierVectorized`: Batch modular multiplication using Java 26 `jdk.incubator.vector` (SIMD)
- `Ciphertext` record: Immutable `(String hexData, Scheme scheme)` — ciphertexts live as hex strings in entity fields

### 3. Native Layer — Project Panama FHE Bridge
- `FheNativeBridge`: FFM downcall handles into `blindbean_fhe.dll` (currently a dummy implementation that would link to Microsoft SEAL in production)
- Supports BFV and CKKS schemes; zero-JNI approach uses `MethodHandle` downcalls
- Native header/source: `src/main/native/blindbean_fhe.{h,c}`

## Key Conventions

- **Ciphertext storage**: Encrypted values are stored as hex strings in entity fields (e.g., `String balance`), opaque to domain logic.
- **ThreadLocal lifecycle**: `BlindContext.init()` initializes a Paillier instance per thread. Tests must call this before encrypting.
- **Scheme dispatch**: New schemes are added by extending `Scheme` enum and adding a case in `BlindMath`.
- **Dummy FHE**: The C DLL is a stub. Real BFV/CKKS would require linking against Microsoft SEAL or OpenFHE.
- **Multi-module Maven**: Root POM aggregates `blindbean-core` (library) and `blindbean-example` (end-to-end demo with `WalletTest`).
