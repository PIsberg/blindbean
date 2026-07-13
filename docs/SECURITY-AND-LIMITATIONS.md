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
  PaillierKeyPair next = new PaillierKeyPair(1024);
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
