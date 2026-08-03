<!-- VIBETAGS-START -->
# Rules for BlindRotation

## PII / Privacy Guardrails
- **Rule**: Never log or expose runtime values of this element.
- **Reason**: Holds two generations of private key material — never log the key pairs, the native key payloads, the decrypted plaintext, or expose them in fixtures

## Test-Driven Requirements
- **Rule**: Changes MUST be accompanied by a matching test update.
- **Coverage Goal**: 90%
- **Frameworks**: JUNIT_5
- **Test Location**: src/test/java/se.deversity.blindbean/context

## Thread-Safety Guarantee
- **Strategy**: OTHER
- **Note**: rotate() is concurrency-safe: PaillierMath is effectively immutable with a thread-safe SecureRandom, and each FheContext serializes its own native calls on nativeLock. The counter is an AtomicLong; commit()/close() are guarded by the session monitor and flip volatile flags that rotate() reads.

## Public API Surface Protection
- **Rule**: Exposes public API. Preserve signature, Javadoc, and behavior without breaking backwards or source compatibility.

## Idempotency Guarantee
- **Rule**: These operations are idempotent. Calling them multiple times must produce the same result as calling them once.

### Rules for method close
- **Reason**: Guarded by the closed flag; repeated close() is a no-op and never disturbs the installed context or double-frees a native context

### Rules for method commit
- **Reason**: The second call observes committed == true and returns; installing the same keys twice must not be an error, and the source is retired once

## Security-Critical Code
- **Rule**: This code is security-critical. Do not weaken security properties. Every change must be explicitly reviewed for security impact.
- **Aspect**: key-rotation
<!-- VIBETAGS-END -->
