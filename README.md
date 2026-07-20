# BlindBean FHE Library

![Java 26](https://img.shields.io/badge/Java-26-orange.svg?logo=java)
![Project Panama FFM](https://img.shields.io/badge/Project_Panama-FFM-blue.svg)
![Cryptography](https://img.shields.io/badge/Cryptography-FHE-red.svg)
![Microsoft SEAL](https://img.shields.io/badge/Microsoft_SEAL-4.1-0078D4.svg)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/PIsberg/blindbean/badge)](https://securityscorecards.dev/viewer/?uri=github.com/PIsberg/blindbean)
[![codecov](https://codecov.io/gh/PIsberg/blindbean/graph/badge.svg?token=Y6W85Z8B6B)](https://codecov.io/gh/PIsberg/blindbean)
[![License](https://img.shields.io/badge/License-PolyForm_Noncommercial_1.0.0-orange.svg)](LICENSE)
[![Pitest Passed](https://img.shields.io/badge/Pitest-Passed-brightgreen.svg)](https://pitest.org)
[![Checkstyle](https://img.shields.io/badge/Checkstyle-passing-brightgreen.svg)](https://checkstyle.org)
[![PMD](https://img.shields.io/badge/PMD-passing-brightgreen.svg)](https://pmd.github.io)
[![SpotBugs](https://img.shields.io/badge/SpotBugs-passing-brightgreen.svg)](https://spotbugs.github.io)
[![ArchUnit](https://img.shields.io/badge/ArchUnit-enforced-brightgreen.svg)](https://www.archunit.org)
[![JSpecify](https://img.shields.io/badge/JSpecify-null--marked-brightgreen.svg)](https://jspecify.dev)
[![NullAway](https://img.shields.io/badge/NullAway-enforced-brightgreen.svg)](https://github.com/uber/NullAway)

> [!NOTE]
> **Pitest Passed**: This repository is fully validated by Pitest mutation testing, ensuring exceptionally strong test quality and mutation coverage.

> [!TIP]
> **Coverage**: BlindBean holds high line and branch coverage across every module — tracked on [Codecov](https://codecov.io/gh/PIsberg/blindbean), with a patch-coverage gate enforced on every pull request. The sunburst below maps coverage per package and file (click through for the live report).

[![Coverage sunburst](https://codecov.io/gh/PIsberg/blindbean/graphs/sunburst.svg?token=Y6W85Z8B6B)](https://codecov.io/gh/PIsberg/blindbean)

BlindBean is a developer-first Java 26 library that makes Homomorphic Encryption (HE) invisible to the end user. It allows you to perform secure, private arithmetic on encrypted data using standard Java objects, completely hiding the complex cryptography behind annotations.

![blind-bean-inforgraphics-v1](https://github.com/user-attachments/assets/de57a253-7b2d-41a9-ae68-8bd58e9af7f7)


## The Vision
If it feels like math, we failed. It feels like Hibernate. You annotate, we calculate.

## Features
- **Pure Java Paillier**: Leverages the Java 26 Vector API (Project Panama SIMD) for parallelized Partially Homomorphic Encryption.
- **Native FHE Bridge**: Supports **BFV** (exact integer) and **CKKS** (approximate real) schemes via Microsoft SEAL 4.3, bridged through Project Panama FFM — zero JNI.
- **Developer-first Annotations**: Simply slap `@Homomorphic` on your domain entities.
- **AutoCloseable Resources**: `FheContext` and `FheCiphertextNative` support try-with-resources for deterministic native cleanup.

## Understanding the Cryptography
If you want to understand the cryptography powering BlindBean, check out these reliable resources:
- [What is Homomorphic Encryption? (IBM)](https://www.ibm.com/topics/homomorphic-encryption)
- [Microsoft SEAL Repository](https://github.com/microsoft/SEAL)
- [Paillier Cryptosystem (Wikipedia)](https://en.wikipedia.org/wiki/Paillier_cryptosystem)
- [HomomorphicEncryption.org Standard](https://homomorphicencryption.org/standard/)

## License — noncommercial only

BlindBean is released under the [PolyForm Noncommercial License 1.0.0](LICENSE).

**Commercial use is not granted.** You may use, modify and redistribute it for
noncommercial purposes — personal projects, research, study, and use by charities,
educational institutions, public research bodies and government. Anything with an
anticipated commercial application is outside the licence.

If you want to use BlindBean commercially, open an issue — there is no commercial
licence on offer today, and this section will say so plainly until there is.

> Earlier versions of this file called the licence "PolyForm Commercial", over the
> same noncommercial text. No such PolyForm licence exists, and the name said the
> opposite of the terms. The terms have not changed; the label was wrong.

## Install

BlindBean is a set of JPMS modules. On the **classpath**, one aggregate coordinate pulls the whole
library:

```xml
<dependency>
    <groupId>se.deversity</groupId>
    <artifactId>blindbean</artifactId>
    <version>0.1.0</version>
    <type>pom</type>
</dependency>
```

On the **module path**, depend on the modules you use (import `blindbean-bom` for versions) and add
`requires`:

```java
requires se.deversity.blindbean.runtime;   // BlindContext, rotation, Paillier — brings fhe/core/annotations
// put se.deversity.blindbean.processor on your --processor-module-path (compile time)
```

Either way the annotation processor is `blindbean-processor`; add it to your compiler's processor
path. It depends on **nothing but the annotations**, so your compile step never pulls the runtime,
the native bridge, or the Vector API.

The jars do **not** bundle the native library. Paillier is pure Java and works out of the box;
BFV/CKKS need `blindbean_fhe` for your platform — take it from the
[release assets](https://github.com/PIsberg/blindbean/releases) and point
`-Dblindbean.native.path` at the directory holding it.

Every JVM running BlindBean needs `--enable-preview --add-modules jdk.incubator.vector`, plus native
access for BFV/CKKS: `--enable-native-access=ALL-UNNAMED` on the classpath, or
`--enable-native-access=se.deversity.blindbean.fhe` on the module path.

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
cmake -S blindbean-fhe/src/main/native -B build-native \
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

// 4. Credit 500.50 — the wrapper encrypts the plaintext for you
wrapper.addBalance(new BigDecimal("500.50")); // Math happens right there, without decryption!
```

Every generated wrapper also accepts pre-encrypted values (`wrapper.addBalance(ciphertext)`), alongside the plaintext overload shown above.

### Testing your entities

Skip the `init()`/`clear()` boilerplate in test suites — annotate the class and every test gets a fresh, automatically-cleaned context:

```java
@BlindBeanTest                                            // Paillier
class WalletTest { ... }

@BlindBeanTest(scheme = Scheme.BFV, polyModulusDegree = 8192)  // + native FHE
class PortfolioTest { ... }
```

### Supported types

The scheme is not a preference — it is decided by the field's type, and the processor fails the build on a wrong pairing. `type()` names the *plaintext* type; the field itself is always a `String` holding hex.

| Field holds | Scheme | Add | Subtract | Multiply |
|:---|:---|:---:|:---:|:---:|
| `byte`, `short`, `int`, `long`, `BigInteger` (+ boxed) | `PAILLIER` | ✅ | ✅ | ❌ |
| `BigDecimal` — **exact** decimals at a fixed `scale` | `PAILLIER` | ✅ | ✅ | ❌ |
| `String` | `PAILLIER` | ❌ | ❌ | ❌ |
| `byte[]` — an opaque blob | `PAILLIER` | ❌ | ❌ | ❌ |
| `boolean` | `PAILLIER` | ❌ | ❌ | ❌ |
| `Instant`, `LocalDate` — *points* in time | `PAILLIER` | ❌ | ❌ | ❌ |
| `Duration` — a *quantity* | `PAILLIER` | ✅ | ✅ | ❌ |
| `float`, `double` (+ boxed) | `CKKS` | ✅ | ✅ | ✅ |
| `float[]`, `double[]` — real vectors | `CKKS` | ✅ | ✅ | ✅ |
| `long[]`, `int[]`, `short[]` — integer vectors | `BFV` | ✅ | ✅ | ✅ |

Subtraction goes wherever addition does. In Paillier it is a multiply by the modular inverse, so
`3 - 10` really is `-7` — not a several-hundred-digit residue (see `decryptSigned`).

```java
@Homomorphic(scheme = Scheme.PAILLIER, type = java.math.BigDecimal.class, scale = 2)
private String price;            // 19.99 stored as the integer 1999

@Homomorphic(scheme = Scheme.CKKS, type = double[].class)
private String signal;           // a whole vector in one ciphertext

@Homomorphic(scheme = Scheme.BFV, type = int[].class)
private String counters;
```

Arithmetic is generated **only where it means something**. Adding two encoded strings or two blobs corrupts them, and "Tuesday plus Thursday" is not a date — so `String`, `byte[]`, `boolean`, `Instant` and `LocalDate` get no `add`/`mul` at all. A `Duration` is a quantity, so it does.

**Money goes in `BigDecimal` on Paillier, never CKKS.** CKKS is approximate; `19.99 + 0.01` may not be exactly `20.00`. Paillier stores the unscaled integer at a fixed scale, so it is exact. A value with more decimals than the scale is **rejected, not rounded** — silently losing a cent is worse than failing.

**Null:** the reference types (`BigDecimal`, `byte[]`, `String`, `java.time`, the arrays) accept null on both sides. Boxed scalars (`Long`, `Double`, …) take the primitive going in, so they are nullable outbound only.

### Vector batching (SIMD arrays)

BFV and CKKS pack a whole vector into a single ciphertext, and one operation applies to every slot at once:

```java
@Homomorphic(scheme = Scheme.BFV, type = long[].class)
private String batchedMetrics;

wrapper.addBatchedMetrics(deltas);   // every slot, one homomorphic op
```

Two limits worth knowing before you rely on this:

- **Slot count.** BFV gives `polyModulusDegree` slots (8,192 at the default). CKKS gives **half** that — complex-conjugate symmetry — so 4,096.
- **A BFV slot is not a `long`.** The plaintext modulus is ~20 bits, so a slot carries roughly **±516,000**: a `long[]` is really a 20-bit int array. Anything larger is rejected with an `FheException` naming the slot. It used to be encrypted anyway — 1,000,000 decrypted as -32,193, and one out-of-range entry corrupted *every other slot in the vector*. Call `FheContext.maxSlotValue()` for the exact limit and scale your values into range.

### Nested entities

An entity that owns another entity reaches through it with `@BlindNested`:

```java
@BlindEntity
public class Order {
    @Homomorphic(scheme = Scheme.PAILLIER, type = java.math.BigDecimal.class, scale = 2)
    private String total;

    @BlindNested
    private UserAccount customer;     // itself a @BlindEntity
}

var order = new OrderBlindWrapper(o);
order.customer().subBalance(new BigDecimal("19.99"));   // straight through, still encrypted
```

The accessor hands back the nested entity's own wrapper, so its whole API — encrypt, decrypt, arithmetic, rotation — is reachable, and each entity keeps its own scheme. A null nested entity yields a null wrapper.

**Records are not supported.** The wrapper stores each ciphertext by calling `setX(...)` on the entity, and a record's components are final. Use a class with a getter and setter per field.

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
