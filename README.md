# BlindBean FHE Library

![Java 26](https://img.shields.io/badge/Java-26-orange.svg?logo=java)
![Project Panama FFM](https://img.shields.io/badge/Project_Panama-FFM-blue.svg)
![Cryptography](https://img.shields.io/badge/Cryptography-FHE-red.svg)
![Microsoft SEAL](https://img.shields.io/badge/Microsoft_SEAL-4.1-0078D4.svg)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/PIsberg/blindbean/badge)](https://securityscorecards.dev/viewer/?uri=github.com/PIsberg/blindbean)
[![codecov](https://codecov.io/gh/PIsberg/blindbean/graph/badge.svg?token=Y6W85Z8B6B)](https://codecov.io/gh/PIsberg/blindbean)
![License](https://img.shields.io/badge/License-PolyForm_Commercial-blue.svg)
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

## Install

```xml
<dependency>
    <groupId>se.deversity</groupId>
    <artifactId>blindbean</artifactId>
    <version>0.1.0</version>
</dependency>
```

The jar does **not** bundle the native library. Paillier is pure Java and works out of the box;
BFV/CKKS need `blindbean_fhe` for your platform — take it from the
[release assets](https://github.com/PIsberg/blindbean/releases) and point
`-Dblindbean.native.path` at the directory holding it.

Every JVM running BlindBean needs:

```
--enable-preview --add-modules jdk.incubator.vector --enable-native-access=ALL-UNNAMED
```

## Prerequisites

Only if you are building from source:

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

// 4. Add 500 — the wrapper encrypts the plaintext for you
wrapper.addBalance(BigInteger.valueOf(500)); // Math happens right there, without decryption!
```

Every generated wrapper also accepts pre-encrypted values (`wrapper.addBalance(ciphertext)`), and BFV/CKKS fields get matching `long`/`double`/`long[]` plaintext overloads.

### Testing your entities

Skip the `init()`/`clear()` boilerplate in test suites — annotate the class and every test gets a fresh, automatically-cleaned context:

```java
@BlindBeanTest                                            // Paillier
class WalletTest { ... }

@BlindBeanTest(scheme = Scheme.BFV, polyModulusDegree = 8192)  // + native FHE
class PortfolioTest { ... }
```

### Storing Arbitrary Types
You can securely store standard Java types like `String`, `boolean` or any numeric type (`byte`, `short`, `int`, `long`, `float`, `double`) natively:
```java
@Homomorphic(scheme = Scheme.PAILLIER, type = int.class)
private String age; 

@Homomorphic(scheme = Scheme.BFV, type = long.class)
private String balance; 

@Homomorphic(scheme = Scheme.CKKS, type = double.class)
private String precisionValue;
```
*Note: Homomorphic math functions (add/multiply) are structurally omitted for textual and logical structures (String/boolean) to prevent mathematical data corruption.*

### Vector Batching (SIMD Arrays)
When using the BFV scheme, you can natively batch complete arrays of thousands of variables homogeneously using the `long[].class` parameter. 
```java
@Homomorphic(scheme = Scheme.BFV, type = long[].class)
private String batchedMetrics; 
```
Math operations (such as `wrapper.addBatchedMetrics(...)`) automatically propagate efficiently to all coordinates concurrently at the underlying C++ layer simultaneously without adding a single millisecond of overhead. Note: Maximum batch capacity is natively bound to the Scheme's polynomial degree size limit (`8,192`).

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

## Using BlindBean from your own build

Until published artifacts ship, install locally (`./mvnw clean install`) and depend on `se.deversity.blindbean:blindbean:1.0-SNAPSHOT`. Your build and runtime must carry the same JVM flags this library is compiled with:

```xml
<!-- maven-compiler-plugin -->
<compilerArgs>
    <arg>--enable-preview</arg>
    <arg>--add-modules</arg><arg>jdk.incubator.vector</arg>
</compilerArgs>
<!-- surefire / your runtime -->
<argLine>--enable-preview --add-modules jdk.incubator.vector --enable-native-access=ALL-UNNAMED</argLine>
```

Point `-Dblindbean.native.path=<dir>` at the built native library for BFV/CKKS (Paillier needs no native code). If loading fails, the error message walks you through the fix.

**IntelliJ note:** enable *Settings → Build → Compiler → Annotation Processors → Enable annotation processing*, and mark `target/generated-sources/annotations` as a generated-sources root so `<Entity>BlindWrapper` classes resolve in the editor.

## Rotating keys

Ciphertexts are bound to the keys that produced them, so rotation means re-encryption.
`BlindRotation` holds both key generations at once — the plaintext exists only inside
`rotate()`, and your thread keeps running on the old keys until you `commit()`:

```java
PaillierKeyPair next = new PaillierKeyPair(2048);

try (BlindRotation rotation = BlindRotation.fromCurrent(next)) {
    for (Wallet w : repository.findAll()) {
        new WalletBlindWrapper(w).rotateBalance(rotation);   // generated for every Paillier field
        repository.save(w);
    }
    rotation.commit();                  // new keys become this thread's context
    BlindContext.exportKeys("keys.bin");
}
```

BFV and CKKS rotate the same way, onto a fresh native context with newly generated SEAL keys:

```java
BlindContext.initBfv(8192);

try (BlindRotation rotation = BlindRotation.fromCurrentFhe()) {   // fresh keys, same params
    for (SensorData d : repository.findAll()) {
        new SensorDataBlindWrapper(d).rotateBatchedReadings(rotation);
        repository.save(d);
    }
    rotation.commit();          // installs the new context, retires the old one
}
```

Every `@Homomorphic` field gets a matching `rotate<Field>(BlindRotation)` on its wrapper, so you
never hand-roll a decrypt/re-encrypt loop and the plaintext never surfaces. A rotated ciphertext
stays a first-class operand — you can keep computing on it. `rotate()` is safe to call
concurrently, and an abandoned session leaves you on your original keys.

Rotation is **not** atomic across your datastore: persisting each rotated value is your job, and
a crash midway leaves some rows on old keys and some on new. Keep the old bundle until the batch
is verified. See [KeyRotationTest](blindbean-example/src/test/java/com/example/KeyRotationTest.java)
for a runnable end-to-end example.

## Security model & limitations

What each scheme does and doesn't give you (no encrypted comparisons, malleability, CKKS approximation), noise-budget rules, and key-rotation guidance: see [docs/SECURITY-AND-LIMITATIONS.md](docs/SECURITY-AND-LIMITATIONS.md).
