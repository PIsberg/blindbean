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

## 3. The Native Layer (FHE & FFM / Project Panama)

For Fully Homomorphic Encryption (FHE) like BFV or CKKS (which require intense polynomials and noise budget routing impossible in Pure Java), we bridge to C++ backends (like Microsoft SEAL).
- **Zero JNI**: We use Java 26 Project Panama (Foreign Function & Memory API - `java.lang.foreign`). 
- **`FheNativeBridge`**: Replicates the layout structs output by Project Panama's `jextract`, loading the `blindbean_fhe.dll`.
- **Performance**: Direct `MethodHandle` invocations pass pointers and structs to the native library at near zero-overhead, allowing "peak vibe coding" without maintaining fragile JNI C-bridges.
