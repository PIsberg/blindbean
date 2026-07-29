# Supported Field Types

> Extracted from `CLAUDE.md` so the always-loaded context stays small. Linked from the topic index there.

The scheme is decided by the field's type, and the processor fails the build on a wrong pairing.
`@Homomorphic(type = X.class)` names the *plaintext* type; the field itself is always a `String`
holding hex.

| Type | Scheme | Arithmetic |
|---|---|---|
| `byte`/`short`/`int`/`long`/`BigInteger` (+ boxed), `BigDecimal`, `Duration` | PAILLIER | add, sub |
| `String`, `byte[]`, `boolean`, `Instant`, `LocalDate` | PAILLIER | none |
| `float`/`double` (+ boxed), `float[]`, `double[]` | CKKS | add, sub, mul |
| `long[]`, `int[]`, `short[]` | BFV | add, sub, mul |

The per-type **encoding** column and the consumer-facing scheme-choice guidance live in the bundled `blindbean` skill, which carries the same mapping in more detail — don't duplicate it here.

Rules worth knowing before adding another type:

- **Arithmetic is generated only where it means something.** `Instant` and `LocalDate` are *points* —
  adding two of them is nonsense — so no `addX` is emitted. `Duration` is a *quantity*, so it is.
  Strings and blobs get none either: adding two encodings corrupts them.
- **Paillier is signed, but only through `decryptSigned`.** Its plaintext space is Z_n, so a raw
  `decrypt` returns a residue and `encrypt(-5)` comes back as `n - 5`. Every *numeric* decode in the
  generated code goes through `PaillierMath.decryptSigned` (balanced representation). Strings and
  `byte[]` must keep using plain `decrypt` — they are unsigned magnitudes, and a blob with the top
  bit set would otherwise read as negative.
- **A BFV slot is ~20 bits, not 64.** `PlainModulus::Batching(degree, 20)` gives t ≈ 1,032,193, so a
  slot holds about ±516,000. `FheContext.encryptLongArray` now rejects anything larger — before the
  guard SEAL reduced it mod t and returned a plausible wrong number, and a single out-of-range entry
  corrupted every other slot in the vector. `maxSlotValue()` reports the limit.
- **CKKS has degree/2 slots**, not degree (complex-conjugate symmetry), and is approximate — never
  use it for money. `BigDecimal` on Paillier is the exact option.
- `byte[]` is deliberately a Paillier **blob**, not a BFV vector; use `short[]`/`int[]` for small
  integer vectors.

**Composition (`@BlindNested`).** A field whose type is itself a `@BlindEntity` gets an accessor
returning that entity's wrapper (`order.customer().subBalance(...)`), so the whole inner API is
reachable without wrapping by hand at every call site. It writes through to the same object; a null
nested entity yields a null wrapper. Explicit by design — the processor does not hunt for
`@BlindEntity`-typed fields on its own, and a field may not be both `@Homomorphic` and
`@BlindNested`.

**Records are unsupported by construction**, not by omission: the wrapper stores each ciphertext with
`entity.setX(hex)`, and a record's components are final. Supporting them means a different generated
API that returns a new record rather than mutating one. The processor rejects them with that reason
rather than a bare "only applies to classes".
