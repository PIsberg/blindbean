# BlindBean FHE Library

![Java 26](https://img.shields.io/badge/Java-26-orange.svg?logo=java)
![Project Panama FFM](https://img.shields.io/badge/Project_Panama-FFM-blue.svg)
![Cryptography](https://img.shields.io/badge/Cryptography-FHE-red.svg)
![Microsoft SEAL](https://img.shields.io/badge/Microsoft_SEAL-4.1-0078D4.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)
BlindBean is a developer-first Java 26 library that makes Homomorphic Encryption (HE) invisible to the end user. It allows you to perform secure, private arithmetic on encrypted data using standard Java objects, completely hiding the complex cryptography behind annotations.

![blind-bean-inforgraphics-v1](https://github.com/user-attachments/assets/de57a253-7b2d-41a9-ae68-8bd58e9af7f7)


## The Vision
If it feels like math, we failed. It feels like Hibernate. You annotate, we calculate.

## Features
- **Pure Java Paillier**: Leverages the Java 26 Vector API (Project Panama SIMD) for parallelized Partially Homomorphic Encryption.
- **Native FHE Bridge**: Supports **BFV** (exact integer) and **CKKS** (approximate real) schemes via Microsoft SEAL 4.1, bridged through Project Panama FFM — zero JNI.
- **Developer-first Annotations**: Simply slap `@Homomorphic` on your domain entities.
- **AutoCloseable Resources**: `FheContext` and `FheCiphertextNative` support try-with-resources for deterministic native cleanup.

## Understanding the Cryptography
If you want to understand the cryptography powering BlindBean, check out these reliable resources:
- [What is Homomorphic Encryption? (IBM)](https://www.ibm.com/topics/homomorphic-encryption)
- [Microsoft SEAL Repository](https://github.com/microsoft/SEAL)
- [Paillier Cryptosystem (Wikipedia)](https://en.wikipedia.org/wiki/Paillier_cryptosystem)
- [HomomorphicEncryption.org Standard](https://homomorphicencryption.org/standard/)

## Prerequisites

| Requirement | Version |
|:------------|:--------|
| JDK | 26-ea (with `--enable-preview`) |
| CMake | 3.16+ |
| vcpkg | Latest |
| C++ compiler | MSVC 2019+ / GCC 11+ / Clang 14+ (C++17) |

## Building

```bash
# 1. Build the native SEAL-backed DLL
cmake -S src/main/native -B build-native \
    -DCMAKE_TOOLCHAIN_FILE=<vcpkg-root>/scripts/buildsystems/vcpkg.cmake
cmake --build build-native --config Release

# 2. Build and install the Java library
./mvnw clean install -B -Dblindbean.native.path=build-native

# 3. Run tests
./mvnw clean test -Dblindbean.native.path=build-native
```

On Windows, use `mvnw.cmd` and `-Dblindbean.native.path=build-native/Release`.

## CI

GitHub Actions runs:
- a fast Java-only gate on Linux and macOS for annotation-processor and core regressions
- a native build matrix on Linux, macOS, and Windows that publishes the built shared library as an artifact
- the full Maven test suite on Windows against the published `blindbean_fhe.dll`

## Quickstart

Add 500 to an encrypted balance in under 5 lines of code:

```java
// 1. Initialize Context
BlindContext.init();

// 2. Fetch or Create Entity
UserAccount user = repository.findById(1); // User whose balance is entirely encrypted!

// 3. Transparently Wrap using the Auto-Generated Helper
UserAccountBlindWrapper wrapper = new UserAccountBlindWrapper(user);

// 4. Add the encrypted amount
Ciphertext amountToAdd = BlindContext.getPaillier().encrypt(BigInteger.valueOf(500));
wrapper.addBalance(amountToAdd); // Math happens right there, without decryption!
```

### Using BFV (Fully Homomorphic — Integers)

```java
try (var ctx = FheContext.bfv(8192)) {
    MemorySegment encrypted = ctx.encryptLong(42L);
    MemorySegment doubled   = ctx.add(encrypted, encrypted);

    long result = ctx.decryptLong(doubled);
    System.out.println("42 + 42 = " + result);  // 84, exact
}
```

### Using CKKS (Fully Homomorphic — Reals)

```java
try (var ctx = FheContext.ckks(8192, Math.pow(2, 40))) {
    MemorySegment encrypted = ctx.encryptDouble(3.14);
    MemorySegment doubled   = ctx.add(encrypted, encrypted);

    double result = ctx.decryptDouble(doubled);
    System.out.println("3.14 + 3.14 ≈ " + result);  // ≈ 6.28
}
```

## Running Benchmarks

We test our throughput against standard `long` additions using JMH.

```bash
./mvnw clean verify
java -jar target/benchmarks.jar
```

*Note: Requires JDK 26 with `--enable-preview` and `--add-modules jdk.incubator.vector` enabled.*
