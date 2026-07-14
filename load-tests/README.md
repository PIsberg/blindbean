# BlindBean Load Tests

Standalone harness — **not** a module of the core reactor, so an ordinary `mvn install` never pays
for it (same arrangement as `vibetags/load-tests`).

| Category | Class | What it measures |
|---|---|---|
| Crypto metrics | `CryptoMetricsTest` | Ciphertext expansion, noise budget → multiplicative depth, CKKS precision decay, batching amortisation, keygen cost by modulus size |
| Concurrency & leaks | `ConcurrentCryptoStressTest` | Thread-local key isolation under 32 virtual threads, foreign-key rejection under load, native-handle lifecycle over thousands of ops |
| Hot-path microbenchmarks | `CryptoHotPathBenchmark` (JMH) | Per-operation cost of encrypt/decrypt/add/multiply across Paillier, BFV and CKKS, plus batched ops |

Throughput alone tells you almost nothing about a homomorphic library. The numbers that decide
whether a design is *viable* are cryptographic: how much your data swells, and how many operations
you can chain before it silently turns to noise. Those are what this harness reports.

## Prerequisite

Install the library into your local repo first:

```bash
cd .. && ./mvnw install -DskipTests -Dblindbean.native.path=build-native/Release
```

FHE sweeps are **skipped, not failed**, when the native library is absent — the Paillier metrics
still run.

## Running

```bash
cd load-tests

# Everything (~2 min)
../mvnw test

# Keep a CI run quick
../mvnw test -Dstress.max.ops=100

# JMH microbenchmarks
../mvnw package -DskipTests
java --enable-preview --add-modules jdk.incubator.vector --enable-native-access=ALL-UNNAMED \
     -Dblindbean.native.path=../build-native/Release \
     -jar target/benchmarks.jar -wi 3 -i 5 -f 1 -tu us -bm avgt -prof gc \
     -rf json -rff results/0.1.0/jmh.json
```

Reports land in `target/*.txt` and print to stdout. Copy them into `results/<version>/` when a
release is cut, so a regression is a diff.

## What 0.1.0 says — and what you should do about it

Full numbers in [`results/0.1.0/`](results/0.1.0/). Four findings worth acting on:

### 1. A single BFV value costs 54,000× its plaintext. Batch, or don't use BFV.

| Scheme | Plaintext | CT bytes | Expansion |
|---|---|---|---|
| Paillier-2048 | `long` | 534 | **67×** |
| BFV-8192 | one `long` (1 slot) | 432,493 | **54,062×** |
| BFV-8192 | `long[8192]` (all slots) | 432,532 | **7×** |
| CKKS-8192 | `double[4096]` (all slots) | 331,596 | **10×** |

A BFV ciphertext is sized by the *parameters*, not the payload: one value costs the same 432 KB as
a full 8,192-slot vector. **Batching is not an optimisation, it is how you stop paying for empty
slots.** If your entity has a single `long` under BFV, you have chosen the worst possible cell in
this table — use Paillier (67×) or fill the slots.

### 2. Batching is a 3,400× speedup, and CKKS only just got it

| Scheme | Mode | Per value |
|---|---|---|
| BFV | scalar (1 value/ct) | 7,334 µs |
| BFV | batched | **2.2 µs** (3,400×) |
| CKKS | scalar | 6,020 µs |
| CKKS | batched | **~6 µs** |

Encrypting values one at a time under BFV/CKKS costs three to four orders of magnitude more than
necessary. The CKKS batched path did not exist before the `double[]` bridge — every CKKS ciphertext
used to waste all but one of its 4,096 slots.

### 3. You get **four** multiplies. Then your data is silently wrong.

| Depth | Noise budget (bits) | Decrypts correctly? |
|---|---|---|
| 0 (encrypt) | 146 | yes |
| 1 | 114 | yes |
| 2 | 83 | yes |
| 3 | 51 | yes |
| 4 | 19 | yes |
| **5** | **0** | **NO — got 49663 instead of 64** |

This is the single most important number in the file. At the default parameters BFV survives **four
chained multiplications**. On the fifth the noise budget hits zero and decryption returns a
plausible wrong number — **no exception, no warning**. Additions are nearly free; multiplies are
what spend the budget.

An application that chains multiplies must watch `FheContext.noiseBudget()`, not just its results.
Nothing else will tell it.

### 4. CKKS holds ~8–9 correct digits over 1,000 additions

Error grows from 9.6e-10 to 5.0e-8 across 1,000 chained adds — fine for signals and ML features,
and still **never** acceptable for money. Use `BigDecimal` on Paillier, which is exact.

### Keygen (per application, not per request)

Paillier keygen: **10 ms** at 1024 bits, **47 ms** at 2048 (the current default), **122 ms** at 3072.
The security upgrade from 1024 to 2048 costs ~37 ms once. If keygen is on your hot path, that's the
bug — export the bundle and reload it.

### Concurrency

32 virtual threads × 500 ops: **zero** key bleed, **zero** foreign ciphertexts silently decrypted
(800/800 correctly refused), and no heap growth across 2,000 native round-trips. `BlindContext` is
thread-local and `getPaillier()` silently mints a *fresh key* on a thread that has none — so a
leak here would produce unreadable ciphertexts rather than an exception. The only assertion that
catches that is "every worker reads back exactly what it wrote", which is what the test does.
