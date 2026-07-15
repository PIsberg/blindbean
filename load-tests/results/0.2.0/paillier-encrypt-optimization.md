# 0.2.0 — Paillier encryption: drop the `g^m` modPow

## What changed

`PaillierMath.encrypt` computed `c = g^m · r^n mod n²` with **two** modular
exponentiations. Because the key uses `g = n+1` (see `PaillierKeyPair`), the first one is
unnecessary: by the binomial theorem `(1+n)^m = 1 + m·n + C(m,2)n² + …`, and every term from
`k ≥ 2` carries an `n²` factor, so

```
g^m ≡ 1 + m·n   (mod n²)
```

for **every** integer `m` (negative included — both sides are periodic in `m` with period `n`).
So `g^m` becomes one multiply-add-reduce instead of a modPow. Only the random blinding `r^n` — the
term that provides semantic security — keeps its exponentiation, untouched. The resulting `c` is the
**identical value**, so ciphertexts stay byte-for-byte compatible with 0.1.0.

## Why it only shows on wide plaintexts

A modPow's cost scales with the **exponent** width. `g^m`'s exponent is the *plaintext* `m`:

- A small integer field (`int`, `long`, a `BigInteger` holding 42) → `m` is a few bits → `g^m` was
  already almost free, and this change does nothing measurable for it.
- A `String`, `byte[]`, or large `BigInteger`/`BigDecimal` field → `m` fills the plaintext space, up
  to ~`n` bits → `g^m` was a **full-width modPow**, roughly the cost of `r^n`. Removing it ~halves
  the encryption.

## Measured (2048-bit key, same machine, same session)

Wall-clock on the measuring box was too noisy to trust (thermal/contention), so this is **process
CPU time** — the CPU-nanoseconds actually consumed, which is runner-independent — reported as the
min of three samples (least-contended = truest cost). See `ResourceUsageTest` for the rationale; the
~8 ms it reports for a Paillier op matches the 0.1.0 release wall-clock number, which is the check
that CPU-time is the right cross-machine metric here.

| Operation | 0.1.0 (`g^m` modPow) | 0.2.0 (binomial) | Change |
|---|---:|---:|---|
| encrypt, 6-bit int plaintext | ~8 200 µs CPU/op | ~8 900 µs CPU/op | none (within noise — `g^m` already free) |
| **encrypt, ~n-width plaintext** (String/`byte[]`) | **18 359 µs CPU/op** | **8 203 µs CPU/op** | **2.24× faster (−55%)** |

`decrypt`, `add`, `subtract` are unchanged by this commit — `decrypt`'s `c^λ mod n²` (a full-width
exponent) remains the read-path bottleneck, and `add` is already a bare modular multiply.

## Correctness

Ciphertexts are identical to 0.1.0, so nothing downstream changes. Verified green with the optimized
code: `PaillierSignedTest` 5/5 (incl. negatives), `BlindMathTest` 13/13 (incl. BFV/cross-scheme), and
`ConcurrentCryptoStressTest` (thousands of concurrent encrypt→decrypt round-trips, each worker reading
back exactly what it wrote — the assertion that catches an encrypt bug).

## Note on the wall-clock tables

The headline `jmh-paillier.txt` in `0.1.0/` is a **wall-clock** table produced on a clean reference
machine. It should be regenerated there at release to sit alongside these numbers; the CPU-time
comparison above is the load-independent evidence of the change. The new `paillierEncryptLarge` JMH
benchmark added in this commit is what a reference-machine re-run should capture.
