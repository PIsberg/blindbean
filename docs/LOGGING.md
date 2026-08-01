# Logging

BlindBean logs through `System.Logger`, the platform logging API in `java.base`. That choice is
load-bearing rather than stylistic: a library that picks SLF4J, Log4j or Logback picks it for every
consumer too, and this one already promises that a consumer's compile path pulls nothing beyond
what it asked for. No `module-info` requires a logging module, and no `pom.xml` gains a dependency.

With no `LoggerFinder` on the path the JDK routes records into `java.util.logging`. That is a
default, not a requirement, and it is why the level names below have a JUL column.

| BlindBean | `System.Logger.Level` | JUL level |
|---|---|---|
| story detail | `DEBUG` | `FINE` |
| main events | `INFO` | `INFO` |
| recoverable trouble | `WARNING` | `WARNING` |
| environment faults | `ERROR` | `SEVERE` |

## Binding it to your stack

SLF4J 2.x ships a `System.LoggerFinder`, so adding it is the whole job:

```xml
<dependency>
  <groupId>org.slf4j</groupId>
  <artifactId>slf4j-jdk-platform-logging</artifactId>
  <version>2.0.17</version>
  <scope>runtime</scope>
</dependency>
```

Without one, configure JUL directly:

```properties
# logging.properties, passed as -Djava.util.logging.config.file=logging.properties
handlers = java.util.logging.ConsoleHandler
se.deversity.blindbean.level = FINE
java.util.logging.ConsoleHandler.level = FINE
```

## What each level is for

**INFO is sparse.** It carries the events an operator wants to see once per lifecycle, each with
the facts that make the line worth having: which key generation is installed, which scheme and
polynomial modulus degree a context was built with, how long key generation took, how many
ciphertexts a rotation moved. Steady-state cryptography logs nothing at INFO. Twenty-five
encrypt/decrypt round trips produce zero INFO records, and a test enforces that, because a
per-operation INFO line is how a log becomes unreadable and expensive at exactly the throughput
where it matters.

**DEBUG tells the story.** Enabled, it should let someone reconstruct a run without a debugger:
context taken and restored across a thread boundary, each ciphertext rotated with a running count,
each encrypt with the plaintext's bit length and sign, whether a signed decode hit the balanced
representation, the noise budget before each BFV decrypt, the async executor starting and stopping.

The story is worth reading, not just collecting. A Paillier rotation of `-7` prints:

```
FINE Paillier decrypt: ciphertext 150 bytes, residue 511 bits, keyTag 285c0fde
FINE Paillier signed decode: negative=true
FINE Paillier encrypt: plaintext 3 bits, sign -1, ciphertext 150 bytes, keyTag 6467e9aa
FINE Rotated PAILLIER ciphertext #2: 150 -> 150 bytes
```

That sequence is `BlindRotation.PaillierEngine`'s central rule, visible from outside the code: it
rotates the *signed* value, not the raw residue. Had it used the raw `decrypt`, the re-encrypt line
would read `plaintext 511 bits, sign 1`, and every negative value in the dataset would have been
replaced by well-formed garbage. The key tag changing from `285c0fde` to `6467e9aa` on the
re-encrypt is the generation handover in the same four lines.

**WARNING** is for conditions that are recoverable but lose data quietly if ignored:

- a rotation session closed without committing after rotating (those values are under the target
  keys while the thread still holds the source keys, and `close()` succeeds silently)
- a wrong-key refusal, which in a rotation re-run is the difference between a refused row and a
  corrupted one
- a BFV noise budget below 10 bits, where the decrypt still works and the next multiply probably
  will not
- a BFV decrypt refused outright on an exhausted budget
- a native key import that failed and left a half-built context to close

**ERROR** is for environment faults the application cannot fix at runtime, currently the native FHE
library failing to load.

Exceptions are not logged where they are thrown and propagated; the caller already has them. The
exceptions to that rule are the four cases above, where an operator watching logs should see the
event even when the caller catches it.

## What is never logged, at any level

No plaintext. No key material. No ciphertext bytes. This is enforced by the guardrails, not by
convention: `KeyBundle.paillierKeyPair` and `KeyBundle.nativeFhePayload` carry an
`@AISecureLogging` OMIT policy, and `BlindRotation` and `KeyBundle` are `@AIPrivacy`-guarded
against logging the key pairs, the native payloads and the decrypted plaintext.

What goes out instead is shape: schemes, byte lengths, bit lengths, signs, counts, durations,
polynomial modulus degree, noise budget, and the key tag, which is a digest of the *public* modulus
and is truncated to four bytes anyway.

The sharp edge is `BlindRotation.PaillierEngine.rotate`, which holds the decrypted plaintext in a
local for the duration of one call, and `PaillierMath.encrypt`, where the plaintext is a parameter.
Both log only derived shapes.

`LoggingBehaviourTest` drives those paths and then reads back every captured record at every level,
asserting that the plaintext, the ciphertexts and the key moduli appear in none of them. It checks
raw log parameters as well as the interpolated message, because a record logged with more arguments
than its pattern consumes drops the extras during formatting while still handing them to every
downstream appender. It also asserts that something *was* captured, so the check cannot pass
vacuously.

A leak here would not be a cosmetic defect. A plaintext balance in an application log is the
disclosure this library exists to prevent, written by the library itself, at DEBUG, on a machine
whose logs are probably shipped somewhere central.

## Cost when disabled

Log statements on per-operation paths are written so a disabled level costs almost nothing. Two
rules, both learned the hard way while adding this:

- Use `Ciphertext.sizeInBytes()`, never `getBytes().length`. `getBytes()` parses the whole hex
  string into a fresh array; `sizeInBytes()` is `hexData.length() / 2`. An unguarded `getBytes()`
  in a DEBUG statement charges every encrypt, decrypt and rotation for a line nobody is reading.
- Guard any statement that builds a string, such as the key-tag hex, with
  `LOG.isLoggable(DEBUG)`.

Argument evaluation happens before the logging framework decides whether the level is enabled, so
"it is only DEBUG" is not an argument for an expensive expression.
