---
name: blindbean
description: Use BlindBean to compute on encrypted data in Java — annotate a field @Homomorphic, operate through the generated wrapper, manage and rotate keys. Covers scheme choice (Paillier / BFV / CKKS), the generated API, key export/rotation, async, and the JUnit extension. Use when adding or changing encrypted fields, choosing a scheme, wiring BlindContext, rotating keys, or debugging FheException / WrongKeyException / "no native library" failures.
---

# BlindBean

Homomorphic encryption behind annotations. You mark a field `@Homomorphic`, and a compile-time
annotation processor generates a `<Entity>BlindWrapper` that encrypts, decrypts, and does maths on
the value **without ever putting the plaintext in the entity**.

```xml
<dependency>
    <groupId>se.deversity</groupId>
    <artifactId>blindbean</artifactId>
    <version>0.1.0</version>
</dependency>
```

Every JVM running BlindBean needs these, including your test runner:

```
--enable-preview --add-modules jdk.incubator.vector --enable-native-access=ALL-UNNAMED
```

Paillier is pure Java and works out of the box. **BFV and CKKS need the native SEAL library**
(`blindbean_fhe.dll/.so/.dylib`) from the release assets, located with
`-Dblindbean.native.path=<dir>`. Without it, any BFV/CKKS call throws `FheException` — the message
tells you what it looked for and where.

---

## 1. Pick the scheme first

The scheme is not a preference; it is decided by the field's type and by what you need to compute.
The processor enforces the pairing and fails the build if you get it wrong.

| Field holds | Scheme | Can add | Can multiply | Notes |
|---|---|---|---|---|
| `long`, `int`, `short`, `byte`, `BigInteger` | `PAILLIER` | ✅ | ❌ | Pure Java, no native lib. The default. |
| `String` | `PAILLIER` | ❌ | ❌ | Encoded, not arithmetic. **Must** be Paillier. |
| `boolean` | `PAILLIER` | ❌ | ❌ | Maths is meaningless, so none is generated. |
| `float`, `double` | `CKKS` | ✅ | ✅ | **Approximate** — see §7. Needs native. |
| `long[]` | `BFV` | ✅ | ✅ | SIMD batching, thousands of slots at once. Needs native. |

**Paillier cannot multiply.** It is additively homomorphic; `BlindMath.multiply` on a Paillier
ciphertext throws `UnsupportedOperationException`. If you need products, the field must be BFV or
CKKS, which means it needs the native library.

There are **no encrypted comparisons** in any scheme. You cannot ask "is the balance > 100" without
decrypting. Design around this before you build on it.

---

## 2. Declare the entity

The encrypted value lives in the entity as a **hex `String`** — that is the storage type, whatever
the logical type is. `type()` tells the processor what the plaintext really is.

```java
import se.deversity.blindbean.annotations.BlindEntity;
import se.deversity.blindbean.annotations.Homomorphic;
import se.deversity.blindbean.annotations.Scheme;

@BlindEntity
public class UserAccount {

    @Homomorphic(scheme = Scheme.PAILLIER, type = long.class)
    private String balance;            // hex ciphertext, NOT a long

    @Homomorphic(scheme = Scheme.CKKS, type = double.class)
    private String riskScore;

    @Homomorphic(scheme = Scheme.BFV, type = long[].class)
    private String readings;           // a whole vector in one ciphertext

    public String getBalance() { return balance; }
    public void setBalance(String balance) { this.balance = balance; }
    // ... getters and setters for the others
}
```

Rules the processor enforces at compile time — all of these are build errors, not runtime surprises:

- the class must not be abstract, and needs a no-arg constructor;
- **the field must be declared `String`** (it holds hex, not the plaintext);
- a public getter *and* setter must exist for each annotated field;
- `String` fields require `PAILLIER`; `float`/`double` require `CKKS`; `long[]` requires `BFV`.

Proxies are **source-generated, not reflective** — no runtime magic, no bytecode weaving. The
wrapper is real code you can read in `target/generated-sources`.

---

## 3. Boot a context, then use the wrapper

`BlindContext` is **thread-local**. Each thread that touches encrypted data needs its own context,
and must `clear()` it afterwards or it leaks the native handle.

```java
BlindContext.init();                       // Paillier, 2048-bit modulus
BlindContext.initBfv(8192);                // BFV   (needs native)
BlindContext.initCkks(8192, Math.pow(2, 40));  // CKKS (needs native)
try {
    ...
} finally {
    BlindContext.clear();                  // idempotent; always do this
}
```

The generated wrapper is named `<Entity>BlindWrapper` and its methods are suffixed with the
capitalised field name:

```java
UserAccount account = new UserAccount();
var w = new UserAccountBlindWrapper(account);

w.encryptBalance(1000L);                   // plaintext in, hex ciphertext into the entity
w.addBalance(500L);                        // add a plaintext — no need to encrypt it yourself
w.addBalance(someCiphertext);              // ...or another ciphertext
long total = w.decryptBalance();           // 1500

Ciphertext ct = w.getCiphertextBalance();  // the raw value, e.g. to persist or rotate
```

Per field `X` you get `encryptX`, `decryptX`, `getCiphertextX`, `rotateX`, and — only where the
algebra allows it — `addX`, `subX`, `mulX`. The maths methods are **overloaded**: one taking a
`Ciphertext`, one taking the plaintext directly.

The signatures follow `type()`: a `long` field gives `encryptX(long)` / `long decryptX()`, a
`long[]` field gives `encryptX(long[])` / `long[] decryptX()`. **Omit `type()` and you get
`BigInteger`**, which is the default — so `@Homomorphic(scheme = Scheme.PAILLIER)` on its own
produces `encryptX(BigInteger)`, not `encryptX(long)`.

**String and boolean fields get no maths methods at all** — only `encrypt`/`decrypt`/
`getCiphertext`/`rotate` — because adding two encoded strings corrupts them.

`BlindMath.add / subtract / multiply` are the same operations on bare `Ciphertext`s, when you are
not going through an entity.

---

## 4. Keys are the whole game

Encrypted data is worthless without the key and unrecoverable if you lose it. `BlindContext.init()`
generates a **fresh key pair every call** — if you restart your app without persisting the keys,
every ciphertext you already wrote is permanently unreadable.

```java
BlindContext.exportKeys("keys.bin");   // do this once, keep the file safe
BlindContext.loadKeys("keys.bin");     // every subsequent boot
```

**Paillier key size:** `PaillierKeyPair(bits)` sizes the *modulus* `n`, splitting `bits` across the
two primes. It is an RSA-style modulus — **2048 is the minimum**
(`BlindContext.DEFAULT_PAILLIER_BITS`), 3072 for a 128-bit-equivalent claim. Do not copy the small
key sizes used in this repo's own tests; those are chosen for keygen speed.

The "128-bit security" figure quoted for BFV/CKKS describes *those parameters*. It says nothing
about your Paillier modulus, which you size yourself.

---

## 5. Rotating keys

There is no in-place re-key: rotation is decrypt-then-encrypt. `BlindRotation` holds both key
generations side by side so plaintext exists only inside `rotate()`, and the thread's context is not
swapped until `commit()`.

```java
PaillierKeyPair next = new PaillierKeyPair(2048);
try (BlindRotation rotation = BlindRotation.fromCurrent(next)) {
    for (UserAccount a : repository.findAll()) {
        try {
            new UserAccountBlindWrapper(a).rotateBalance(rotation);
            repository.save(a);
        } catch (WrongKeyException alreadyRotated) {
            // this row moved in an earlier, interrupted run — skip it
        }
    }
    rotation.commit();                 // new keys become this thread's context
    BlindContext.exportKeys("keys.bin");   // PERSIST THEM, or you just lost everything
}
```

BFV/CKKS rotate the same way via `BlindRotation.fromCurrentFhe()` (fresh SEAL keys, same
parameters), or `BlindRotation.fhe(source, target)` for two explicit contexts.

**Rotation is not atomic across your datastore.** Persisting each value is yours to do, and a crash
midway leaves some rows old and some new. Keep the old key bundle until the batch is verified.
Re-running the batch **is** safe: every ciphertext is stamped with the key generation that produced
it, so an already-rotated row raises `WrongKeyException` instead of being rotated twice — catch it
and skip, as above.

That stamp matters more than it looks. Neither Paillier nor SEAL *fails* on a foreign ciphertext —
they decrypt it to a plausible wrong value. Without the check, rotating a row twice would silently
replace real data with well-formed garbage.

`commit()` is terminal: rotating under the retired keys afterwards is refused.

---

## 6. Async and testing

Async is **opt-in**, behind the `blindbean.apt.async` processor flag (default off). With it on, every
wrapper method gains an `Async` twin:

```java
CompletableFuture<Void>       f1 = w.encryptBalanceAsync(BigInteger.valueOf(1000));
CompletableFuture<BigInteger> f2 = w.decryptBalanceAsync();

// or drive anything through the executor yourself:
CompletableFuture<Long> f3 = BlindAsync.supplyAsync(() -> w.decryptBalance());
```

`BlindContext` is thread-local, so a task running on another thread has **no context at all** unless
you carry one over — use `BlindContext.snapshot()` / `restore()` across the boundary, or the task
will silently auto-init a *fresh* Paillier key and write ciphertexts nobody can read.

In tests, prefer the JUnit extension over hand-rolled setup — it manages the whole lifecycle:

```java
@BlindBeanTest                                              // Paillier defaults
@BlindBeanTest(scheme = Scheme.BFV, polyModulusDegree = 8192)
@BlindBeanTest(scheme = Scheme.CKKS, polyModulusDegree = 8192, ckksScale = 1099511627776.0)
class MyTest { ... }
```

Nested classes inherit the enclosing annotation.

---

## 7. Things that will bite you

- **CKKS is approximate.** `encrypt(3.14159)` then `decrypt` does not return exactly `3.14159`.
  Always assert with a tolerance. Never use CKKS for money or anything requiring an exact value —
  use Paillier (`long`) for that.
- **Noise budget.** Every homomorphic operation adds noise; exceed the budget and the ciphertext
  stops decrypting to anything meaningful. Multiplications are far more expensive than additions.
  Check `FheContext.noiseBudget(...)` on long operation chains.
- **Ciphertexts are malleable.** Anyone holding one can add to it. Homomorphic encryption gives you
  *confidentiality*, not integrity or authenticity — if that matters, sign or MAC the value
  separately.
- **Ciphertext expansion.** A ciphertext is far larger than the plaintext (SEAL ones run to hundreds
  of kilobytes). Size your columns accordingly.
- **`FheContext` is `AutoCloseable`** and owns native memory. Use try-with-resources, or let
  `BlindContext.clear()` do it. Leaking it leaks native heap, which the GC will not reclaim.
- **`WrongKeyException`** always means the ciphertext belongs to a different key generation. In
  practice: a rotation re-run (skip the row), or the wrong key bundle loaded.
- **`FheException` at startup** is nearly always the missing native library. The message states the
  detected OS/arch, whether `blindbean.native.path` was set, and where it looked — read it, it is
  written to be actionable.

See `docs/SECURITY-AND-LIMITATIONS.md` in the repo for the full statement of what each scheme does
and does not protect.
