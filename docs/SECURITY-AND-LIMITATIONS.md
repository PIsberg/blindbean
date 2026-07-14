# Security Model & Limitations

What BlindBean's schemes give you, what they deliberately do not, and the
operational rules that keep encrypted math correct. Read this before putting
encrypted fields in production.

## What each scheme provides

| | Paillier | BFV | CKKS |
|---|---|---|---|
| Data | Arbitrary-precision integers | Exact 64-bit integers & `long[]` batches | Approximate reals |
| Add / Subtract (ciphertext ⊕ ciphertext) | ✅ | ✅ | ✅ |
| Multiply (ciphertext ⊗ ciphertext) | ❌ (partially homomorphic) | ✅ | ✅ |
| Exactness | Exact | Exact | **Approximate** — expect small floating error (scale-dependent) |
| Backend | Pure Java (+ Vector API acceleration) | Microsoft SEAL (native) | Microsoft SEAL (native) |
| Security target | Key-size dependent | 128-bit (HomomorphicEncryption.org standard params) | 128-bit (same) |

## What no scheme here provides

- **Comparisons and branching on encrypted data.** There is no `<`, `==`,
  `min`, or conditional logic over ciphertexts. If your workflow needs
  "is the encrypted balance below X?", that decision must happen after
  decryption by a key holder, or be redesigned.
- **Integrity or authenticity.** These schemes are malleable *by design* —
  that is what makes the math work. Anyone who can write to a stored
  ciphertext can meaningfully alter the plaintext it decrypts to (e.g. add a
  known value). Protect stored ciphertexts with ordinary integrity controls
  (signatures/MACs at the record level, database permissions, audit).
- **Protection from the key holder.** This is confidentiality *in use*
  against parties who compute on the data — not against whoever holds the
  private key.
- **String/boolean math.** Encrypted storage of `String`/`boolean` is
  supported, but the processor deliberately generates no `add*`/`multiply*`
  for them; arithmetic on encoded text would corrupt it silently.

## Operational rules

### Noise budget (BFV/CKKS)

Every native ciphertext carries a finite noise budget; each operation —
especially multiplication — spends some. When it hits zero, **decryption
returns garbage, not an error**. `FheContext.noiseBudget(ct)` exposes the
remaining budget (also surfaced as the `fhe.noise_budget` metric); check it
in long computation chains and re-encrypt (bootstrap-by-decrypt at a trusted
point) before it runs out. With the default `polyModulusDegree = 8192`,
budget comfortably covers additive workloads and shallow multiplication
depth; deep circuits need explicit budget management.

### CKKS approximation

CKKS is approximate by construction: `3.14 + 3.14` decrypts to *≈* `6.28`.
The `scale` parameter (default 2^40 in the examples) trades precision
against budget. Never use CKKS for values that must round-trip exactly
(money in integer cents belongs in BFV or Paillier).

### Parameters are security floors

The shipped parameters target 128-bit security. Do not lower
`polyModulusDegree` below 8192 or weaken the coefficient modulus to gain
speed — that silently downgrades the security level of every ciphertext
produced under the context.

### Key management

- `BlindContext.exportKeys(path)` / `loadKeys(path)` serialize the full key
  bundle **including private key material**. Treat the file like a private
  key: filesystem permissions, encrypted volumes, never in VCS, never in
  logs.
- Rotation is re-encryption: there is no in-place re-key. Use
  `BlindRotation`, which holds the old and new key generations side by side
  so plaintext exists only inside `rotate()` and the thread's context is not
  swapped until you `commit()`:

  ```java
  PaillierKeyPair next = new PaillierKeyPair(2048);
  try (BlindRotation rotation = BlindRotation.fromCurrent(next)) {
      for (Wallet w : repository.findAll()) {
          new WalletBlindWrapper(w).rotateBalance(rotation);  // generated hook
          repository.save(w);
      }
      rotation.commit();                 // new keys become this thread's context
      BlindContext.exportKeys("keys.bin");
  }
  ```

  BFV and CKKS rotate the same way, through a second native context holding
  fresh SEAL keys — `BlindRotation.fromCurrentFhe()` derives it from the
  installed context's scheme and parameters, or pass two contexts explicitly
  with `BlindRotation.fhe(source, target)`. A BFV ciphertext carries every
  batch slot, so single values and batches rotate identically, and a rotated
  ciphertext remains a first-class operand under the new keys.

  Rotation is **not** atomic across your datastore: persisting each rotated
  value is yours to do, and a crash midway leaves some rows under the old
  keys and some under the new. Keep the old bundle until the batch has been
  verified, and retire it only afterwards. An abandoned (uncommitted)
  session leaves the installed context untouched and frees any context it
  created, so a failed batch cannot strand you without working keys.
  `commit()` is terminal: it installs the new keys, closes the retired
  native context, and refuses further rotation under the old keys.

  **Re-running an interrupted batch is safe.** Rows that already moved are
  refused with a `WrongKeyException` instead of being rotated a second time —
  catch it and skip them:

  ```java
  for (Wallet w : repository.findAll()) {
      try {
          new WalletBlindWrapper(w).rotateBalance(rotation);
          repository.save(w);
      } catch (WrongKeyException alreadyRotated) {
          // this row moved before the crash — leave it alone
      }
  }
  ```

### Ciphertexts are bound to their key generation

Every ciphertext carries a 16-byte stamp identifying the keys that produced
it (`KeyTag`), and decryption, homomorphic operations and rotation all refuse
one that belongs to a different generation.

This is not belt-and-braces: **neither scheme fails on a foreign ciphertext.**
Paillier decryption under the wrong key is well-defined — by the Carmichael
property `c^λ ≡ 1 (mod n)` for any `c` coprime to `n`, so `L()` divides
exactly and you get a plausible wrong number back. SEAL is no better: two
contexts built from the same parameters share a `parms_id`, so a ciphertext
from one deserializes cleanly into the other and decrypts to noise. Without
the stamp, rotating an already-rotated value replaced real data with
well-formed garbage, undetectably, and unrecoverably once the old key was
retired.

The stamp is a truncated SHA-256 over key material with domain separation —
for Paillier the *public* modulus, for BFV/CKKS the serialized SEAL key blob.
It is derived, not randomly assigned, so it survives an
`exportKeys`/`loadKeys` round trip; a random id would be regenerated on
restart and the context would then repudiate its own ciphertexts.

Ciphertexts written before stamping existed carry no header. They are read as
**legacy** and still decrypt — refusing them would make existing data
unreadable — so a dataset heals as it is rewritten, but an un-rewritten legacy
row does not yet have this protection.

### The BFV plaintext modulus bounds every slot

BFV slots are values mod `t`, the plaintext modulus. The default parameters ask
`PlainModulus::Batching(degree, 20)` for a **20-bit** `t` (1,032,193), so a slot
carries roughly **±516,000** — a `long[]` field is really a 20-bit int array.

This used to fail silently and destructively. SEAL's `BatchEncoder` reduces an
out-of-range value mod `t` without complaint, so 1,000,000 decrypted as -32,193,
and a *single* out-of-range entry corrupted **every other slot in the vector**.
`FheContext.encryptLongArray` now rejects such values with an `FheException`
naming the offending slot; `maxSlotValue()` reports the limit. If you need wider
values, raise the plaintext modulus (at the cost of noise budget) or decompose
across ciphertexts.

### Paillier is signed only through `decryptSigned`

Paillier's plaintext space is Z_n. A raw `decrypt` therefore returns a residue in
[0, n): `encrypt(-5)` comes back as `n - 5`, a several-hundred-digit positive
integer. The generated wrappers decode every *numeric* field through
`PaillierMath.decryptSigned`, which applies the balanced representation (residues
above n/2 are negative) — the convention the additive homomorphism already obeys,
so `encrypt(-5) + 7` still decrypts as 2.

Strings and `byte[]` are encoded as **unsigned magnitudes** and must keep using
plain `decrypt`; reading them signed would turn any blob whose leading bit is set
into a negative number.

### Exact decimals

CKKS is approximate and must never hold money. Use `BigDecimal` on Paillier: it is
stored as the unscaled integer at a fixed `scale`, so `19.99 + 0.01` is exactly
`20.00`. The scale is part of the storage format — changing it makes every value
already written decode at the wrong magnitude — and a value with more decimals
than the scale is rejected rather than rounded.

### Noise budget: you get four multiplies

Every homomorphic operation spends noise budget. At zero, the ciphertext stops
decrypting to anything meaningful — **with no exception and no warning**.

Measured at the default BFV parameters (`load-tests`, see `results/0.1.0/`):

| Depth | Noise budget | Correct? |
|:------|:-------------|:---------|
| 0 (encrypt) | 146 bits | yes |
| 4 multiplies | 19 bits | yes |
| **5 multiplies** | **0 bits** | **NO — returns a plausible wrong number** |

So BFV survives **four chained multiplications** at these parameters. Additions
are nearly free; multiplies are what spend the budget. An application that chains
multiplies must watch `FheContext.noiseBudget()` — nothing else will tell it the
answer has gone wrong.

CKKS holds roughly 8-9 correct decimal digits over 1,000 chained additions. Fine
for signals and ML features; never acceptable for money.

### Ciphertext expansion

A BFV ciphertext is sized by the parameters, not the payload: a single `long`
costs the same ~432 KB as a full 8,192-slot vector — an expansion of **54,000x**
for one value, versus **7x** when the slots are filled. Paillier-2048 is 67x.
Batching is not an optimisation; it is how you stop paying for empty slots.

### Paillier key size

`PaillierKeyPair(bits)` sizes the **modulus** `n`, splitting `bits` across the
two primes. Paillier's hardness is factoring `n`, so size it like an RSA
modulus: **2048 is the minimum** (`BlindContext.DEFAULT_PAILLIER_BITS`), and
3072 is what backs a 128-bit-equivalent claim. The 1024-bit default this
library previously shipped is ~80-bit security, which NIST disallowed after
2013.

Note the "128-bit security" figure quoted for the BFV/CKKS parameters is a
statement about **those** parameters (per the HomomorphicEncryption.org
standard) and says nothing about your Paillier modulus, which you size
yourself.
- Ciphertexts cannot move between parameter sets. Rotation requires the
  source and target contexts to share a scheme and `polyModulusDegree`;
  mismatches are rejected up front.
- Ciphertexts are bound to the keys and (for BFV/CKKS) the context
  parameters that produced them; a ciphertext from one context cannot be
  operated on under another.

### Threading

`BlindContext` state is thread-local; use `snapshot()`/`restore()` to move
it across virtual-thread boundaries, and prefer the provided async paths for
concurrent FHE work. Native contexts are internally synchronized but a
single context serializes its native calls — for throughput, use one context
per worker rather than sharing one across many threads.

## Reporting

Security reports: use GitHub private vulnerability reporting on this
repository rather than public issues.
