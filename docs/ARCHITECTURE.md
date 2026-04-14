# Architecture: BlindBean

BlindBean is structurally tiered into three layers to maintain high Developer Experience (DX) without compromising crypto-performance.

## 1. The Developer Layer (Annotations & Proxies)

At compile time, `HomomorphicProcessor` evaluates classes annotated with `@BlindEntity`. It automatically generates heavily optimized wrapper proxies (e.g., `UserAccountBlindWrapper`).
- **No Reflection**: By generating source code rather than using runtime weaving or reflection APIs, we avoid runtime performance hits. The wrappers statically bind to the entity's getters/setters.
- **Transparent Invocation**: When the developer calls `wrapper.addBalance(amount)`, the proxy manages the complexity of extracting the ciphertext, executing homomorphic math, and re-setting the ciphertext, keeping the entity object completely clean.

## 2. The Pure-Java Layer (PHE & Vector API)

For Partial Homomorphic Encryption (PHE) schemes like **Paillier**, the math natively operates on large numbers.
- We implement `PaillierMath` for straightforward `add()` logic utilizing `java.math.BigInteger` under the hood.
- **Java 26 Vector API**: To overcome large overheads of parallel encryptions in large datasets, `PaillierVectorized` abstracts the workload onto SIMD (Single Instruction Multiple Data) lanes using Project Panama's `jdk.incubator.vector`. This ensures multi-lane primitive multiplications drastically outperform standard iteration for scaling workloads.

## 3. The Native Layer (FHE & Microsoft SEAL)

For Fully Homomorphic Encryption (FHE) like BFV or CKKS (which require intense polynomials and noise budget management impossible in Pure Java), we bridge to **Microsoft SEAL 4.1** via a C++ backend.

### SEAL Integration
- **Zero JNI**: We use Java 26 Project Panama (Foreign Function & Memory API — `java.lang.foreign`).
- **`FheNativeBridge`**: Provides 15 cached `MethodHandle` downcalls into `blindbean_fhe.dll`, resolved once at class-load time.
- **`blindbean_fhe.cpp`**: C++ source linking against Microsoft SEAL. All functions are `extern "C"` to maintain a stable ABI.
- **Performance**: Direct `MethodHandle` invocations pass pointers and structs to the native library at near zero-overhead.

### Internal Architecture: `BlindBeanContext`

The opaque `FheContext` handle points to a C++ struct that holds all SEAL objects:

```cpp
struct BlindBeanContext {
    seal::SEALContext*   sealCtx;      // Encryption parameter context
    seal::Encryptor*     encryptor;    // Public-key encryptor
    seal::Decryptor*     decryptor;    // Secret-key decryptor
    seal::Evaluator*     evaluator;    // Homomorphic operations
    seal::PublicKey       publicKey;
    seal::SecretKey       secretKey;
    seal::RelinKeys       relinKeys;   // For post-multiply relinearization
    double                scale;       // CKKS scale parameter
    bool                  isCkks;      // Scheme flag
};
```

### Memory Management

- **Java side**: `FheContext` and `FheCiphertextNative` implement `AutoCloseable`, enabling try-with-resources for deterministic cleanup.
- **Native side**: `fhe_destroy_context()` deletes all SEAL objects; `fhe_free_ciphertext()` deletes individual `seal::Ciphertext*` instances.
- **Arena management**: Java `Arena` instances scope the lifecycle of off-heap memory segments returned by native calls.

### Supported Operations

| Operation | BFV | CKKS |
|:----------|:---:|:----:|
| Encrypt/Decrypt | ✅ int64 | ✅ double |
| Addition | ✅ exact | ✅ approximate |
| Multiplication | ✅ exact + auto-relin | ✅ approximate + rescale |
| Noise Budget | ✅ real bits | ❌ returns -1 |
| Serialization | ✅ | ✅ |

### Build System

The native DLL is built via **CMake** with **vcpkg** for dependency management:
```bash
cmake -S src/main/native -B build-native \
    -DCMAKE_TOOLCHAIN_FILE=<vcpkg>/scripts/buildsystems/vcpkg.cmake
cmake --build build-native --config Release
```

SEAL is linked as a static library, so the resulting `blindbean_fhe.dll` is self-contained.
