---
paths: ["**/context/*.java"]
---

<!-- VIBETAGS-START -->
# Rules for context-and-keys

## se.deversity.blindbean.context.KeyBundle

### Rules for field serialVersionUID
- **Reason**: Serialization UID — altering this invalidates all persisted key bundles and breaks key import/export across versions

## PII / Privacy Guardrails
- **Rule**: Never log or expose runtime values of this element.
- **Reason**: Contains serialized Paillier private key material and SEAL key bytes — never log, transmit in plaintext, or expose field values in suggestions or test fixtures

## Schema & Serialization Safety
- **Rule**: Prohibit altering data formats, fields, database columns, or serialization structures without explicit backward-compatible migration paths.

## Access Restrictions
- **Allowed Callers**: [se.deversity.blindbean.context.BlindContext]

### Rules for field paillierKeyPair
- **Policy**: OMIT
- **Rule**: Never pass this raw variable to log appenders or stdout streams.

### Rules for field nativeFhePayload
- **Policy**: OMIT
- **Rule**: Never pass this raw variable to log appenders or stdout streams.

## se.deversity.blindbean.context.BlindContext

## Security Audit Requirements
When modifying this element, audit for:
- Resource Leaks
- Thread Safety
- Context Closure failures

## Core Functionality
- **Sensitivity**: High
- **Note**: Well-tested core functionality. Make changes with extreme caution.

## Test-Driven Requirements
- **Rule**: Changes MUST be accompanied by a matching test update.
- **Coverage Goal**: 90%
- **Frameworks**: JUNIT_5
- **Test Location**: src/test/java/se.deversity.blindbean/context

## Thread-Safety Guarantee
- **Strategy**: THREAD_LOCAL
- **Note**: Paillier and FHE state isolated in ThreadLocal fields; snapshot()/restore() required to propagate across virtual-thread boundaries

## Public API Surface Protection
- **Rule**: Exposes public API. Preserve signature, Javadoc, and behavior without breaking backwards or source compatibility.

### Rules for method clear
- **Rule**: This operation is idempotent. Calling it multiple times must produce the same result as calling it once.
- **Reason**: ThreadLocal.remove() and FheContext.close() are both safe to call when no state is present

## Security-Critical Code
- **Rule**: This code is security-critical. Do not weaken security properties. Every change must be explicitly reviewed for security impact.
- **Aspect**: key-management

### Rules for method exportKeys
- **Rule**: This code is security-critical. Do not weaken security properties. Every change must be explicitly reviewed for security impact.
- **Aspect**: key-serialization

### Rules for method loadKeys
- **Rule**: This code is security-critical. Do not weaken security properties. Every change must be explicitly reviewed for security impact.
- **Aspect**: key-deserialization

### Rules for parameter BlindContext.exportKeys(java.lang.String)#filePath
- **Target Filters**: PATH_TRAVERSAL
- **Rule**: Run raw input strings through approved sanitizers.

### Rules for parameter BlindContext.loadKeys(java.lang.String)#filePath
- **Target Filters**: PATH_TRAVERSAL
- **Rule**: Run raw input strings through approved sanitizers.

## se.deversity.blindbean.context.BlindRotation

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

### Rules for method commit
- **Rule**: This operation is idempotent. Calling it multiple times must produce the same result as calling it once.
- **Reason**: The second call observes committed == true and returns; installing the same keys twice must not be an error, and the source is retired once

### Rules for method close
- **Rule**: This operation is idempotent. Calling it multiple times must produce the same result as calling it once.
- **Reason**: Guarded by the closed flag; repeated close() is a no-op and never disturbs the installed context or double-frees a native context

## Security-Critical Code
- **Rule**: This code is security-critical. Do not weaken security properties. Every change must be explicitly reviewed for security impact.
- **Aspect**: key-rotation
<!-- VIBETAGS-END -->
