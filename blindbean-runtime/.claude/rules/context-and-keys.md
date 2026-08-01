---
paths: ["**/context/*.java"]
---

<!-- VIBETAGS-START -->
# Rules for context-and-keys

## Locked Status

### se.deversity.blindbean.context.KeyBundle.serialVersionUID
- **Reason**: Serialization UID — altering this invalidates all persisted key bundles and breaks key import/export across versions

## PII / Privacy Guardrails
- **Rule**: Never log or expose runtime values of these elements.

### se.deversity.blindbean.context.BlindRotation
- **Reason**: Holds two generations of private key material — never log the key pairs, the native key payloads, the decrypted plaintext, or expose them in fixtures

### se.deversity.blindbean.context.KeyBundle
- **Reason**: Contains serialized Paillier private key material and SEAL key bytes — never log, transmit in plaintext, or expose field values in suggestions or test fixtures

## Schema & Serialization Safety

### se.deversity.blindbean.context.KeyBundle
- **Rule**: Prohibit altering data formats, fields, database columns, or serialization structures without explicit backward-compatible migration paths.

## Access Restrictions

### se.deversity.blindbean.context.KeyBundle
- **Allowed Callers**: [se.deversity.blindbean.context.BlindContext]

## Secure Logging Masking
- **Policy**: OMIT
- **Rule**: Never pass these raw variables to log appenders or stdout streams.
- **Applies to**: `se.deversity.blindbean.context.KeyBundle.nativeFhePayload`, `se.deversity.blindbean.context.KeyBundle.paillierKeyPair`

## Security Audit Requirements

### se.deversity.blindbean.context.BlindContext
When modifying this element, audit for:
- Resource Leaks
- Thread Safety
- Context Closure failures

## Core Functionality

### se.deversity.blindbean.context.BlindContext
- **Sensitivity**: High
- **Note**: Well-tested core functionality. Make changes with extreme caution.

## Test-Driven Requirements
- **Rule**: Changes MUST be accompanied by a matching test update.
- **Coverage Goal**: 90%
- **Frameworks**: JUNIT_5
- **Test Location**: src/test/java/se.deversity.blindbean/context
- **Applies to**: `se.deversity.blindbean.context.BlindContext`, `se.deversity.blindbean.context.BlindRotation`

## Thread-Safety Guarantee

### se.deversity.blindbean.context.BlindContext
- **Strategy**: THREAD_LOCAL
- **Note**: Paillier and FHE state isolated in ThreadLocal fields; snapshot()/restore() required to propagate across virtual-thread boundaries

### se.deversity.blindbean.context.BlindRotation
- **Strategy**: OTHER
- **Note**: rotate() is concurrency-safe: PaillierMath is effectively immutable with a thread-safe SecureRandom, and each FheContext serializes its own native calls on nativeLock. The counter is an AtomicLong; commit()/close() are guarded by the session monitor and flip volatile flags that rotate() reads.

## Public API Surface Protection
- **Rule**: Exposes public API. Preserve signature, Javadoc, and behavior without breaking backwards or source compatibility.
- **Applies to**: `se.deversity.blindbean.context.BlindContext`, `se.deversity.blindbean.context.BlindRotation`

## Idempotency Guarantee
- **Rule**: These operations are idempotent. Calling them multiple times must produce the same result as calling them once.

### se.deversity.blindbean.context.BlindContext.clear()
- **Reason**: ThreadLocal.remove() and FheContext.close() are both safe to call when no state is present

### se.deversity.blindbean.context.BlindRotation.close()
- **Reason**: Guarded by the closed flag; repeated close() is a no-op and never disturbs the installed context or double-frees a native context

### se.deversity.blindbean.context.BlindRotation.commit()
- **Reason**: The second call observes committed == true and returns; installing the same keys twice must not be an error, and the source is retired once

## Security-Critical Code
- **Rule**: This code is security-critical. Do not weaken security properties. Every change must be explicitly reviewed for security impact.

### se.deversity.blindbean.context.BlindContext
- **Aspect**: key-management

### se.deversity.blindbean.context.BlindContext.exportKeys(java.lang.String)
- **Aspect**: key-serialization

### se.deversity.blindbean.context.BlindContext.loadKeys(java.lang.String)
- **Aspect**: key-deserialization

### se.deversity.blindbean.context.BlindRotation
- **Aspect**: key-rotation

## Input Sanitization
- **Target Filters**: PATH_TRAVERSAL
- **Rule**: Run raw input strings through approved sanitizers.
- **Applies to**: `se.deversity.blindbean.context.BlindContext.exportKeys(java.lang.String)#filePath`, `se.deversity.blindbean.context.BlindContext.loadKeys(java.lang.String)#filePath`
<!-- VIBETAGS-END -->
