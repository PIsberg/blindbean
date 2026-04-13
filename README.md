# BlindBean FHE Library

BlindBean is a developer-first Java 26 library that makes Homomorphic Encryption (HE) invisible to the end user. It allows you to perform secure, private arithmetic on encrypted data using standard Java objects, completely hiding the complex cryptography behind annotations.

## The Vision
If it feels like math, we failed. It feels like Hibernate. You annotate, we calculate.

## Features
- **Pure Java Paillier**: Leverages the Java 26 Vector API (Project Panama SIMD) for parallelized Partially Homomorphic Encryption.
- **Native FHE Bridge**: Supports BFV and CKKS schemes via a Project Panama `jextract` bridge.
- **Developer-first Annotations**: Simply slap `@Homomorphic` on your domain entities.

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

## Running Benchmarks

We test our throughput against standard `long` additions using JMH.

```bash
mvn clean verify
java -jar target/benchmarks.jar
```

*Note: Requires JDK 26 with `--enable-preview` and `--add-modules jdk.incubator.vector` enabled.*
