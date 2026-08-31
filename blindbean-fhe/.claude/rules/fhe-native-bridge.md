---
paths: ["**/fhe/*.java"]
---

<!-- VIBETAGS-START -->
# Rules for fhe-native-bridge

## Locked Status

### se.deversity.blindbean.fhe.FheNativeBridge
- **Reason**: Direct Memory FFM JNI mapping. Avoid breaking SEAL bridge architecture.

## Core Functionality
- **Sensitivity**: High
- **Note**: Well-tested core functionality. Make changes with extreme caution.
- **Applies to**: `se.deversity.blindbean.fhe.FheContext`, `se.deversity.blindbean.fhe.FheNativeBridge`

## Context & Focus

### se.deversity.blindbean.fhe.FheContext.initNative(java.util.function.Supplier<java.lang.foreign.MemorySegment>)
- **Focus**: Every native context entry point must be routed through this helper so the missing-library failure — the first error most new users hit — stays actionable
- **Avoid**: Calling FheNativeBridge init symbols directly from a factory, which would surface a bare UnsatisfiedLinkError with no remediation guidance

## Performance Constraints
- **Rule**: Optimal complexity required. O(n^2) is forbidden on hot paths.
- **Constraint**: Strict time/space complexity constraints apply. Suboptimal complexity is unacceptable.
- **Applies to**: `se.deversity.blindbean.fhe.FheContext.encryptLongArray(long[])`, `se.deversity.blindbean.fhe.FheContext.multiply(java.lang.foreign.MemorySegment,java.lang.foreign.MemorySegment)`

## Contract-Frozen Signature
- **Constraint**: You may change internal logic, but MUST NOT modify the method name, parameters, return type, or checked exceptions.

### se.deversity.blindbean.fhe.FheCiphertextNative
- **Reason**: Serialization format and handle lifecycle are part of the public FFM contract; do not change method signatures

### se.deversity.blindbean.fhe.FheContext
- **Reason**: Public FHE API consumed by generated BlindWrapper classes; any signature change requires processor regeneration and a major version bump

## Test-Driven Requirements

### se.deversity.blindbean.fhe.FheContext
- **Rule**: Changes MUST be accompanied by a matching test update.
- **Coverage Goal**: 90%
- **Frameworks**: JUNIT_5
- **Test Location**: src/test/java/se.deversity.blindbean/fhe

## Thread-Safety Guarantee

### se.deversity.blindbean.fhe.FheContext
- **Strategy**: SYNCHRONIZED
- **Note**: All native FFM operations are guarded by nativeLock to prevent concurrent SEAL context access

## Observability Instrumentation

### se.deversity.blindbean.fhe.FheContext.noiseBudget(java.lang.foreign.MemorySegment)
- **Rule**: Do not remove or rename instrumentation without flagging the affected dashboard.
- **Details**: Metrics: fhe.noise_budget. Note: Noise budget drives correctness alerts — dashboards fire when budget drops below safe threshold; do not remove or rename this method

## Strict Exception Handling
- **Rule**: Robust exception handling required. Prohibit catching/throwing generic Exception/Throwable. Use descriptive, specific/custom exceptions.
- **Applies to**: `se.deversity.blindbean.fhe.FheCiphertextNative`

### se.deversity.blindbean.fhe.FheContext.initNative(java.util.function.Supplier<java.lang.foreign.MemorySegment>)
- **Reason**: Only linkage errors may be translated here; a genuine SEAL failure must not be disguised as a missing-library problem

## Idempotency Guarantee
- **Rule**: These operations are idempotent. Calling them multiple times must produce the same result as calling them once.

### se.deversity.blindbean.fhe.FheCiphertextNative.close()
- **Reason**: Guarded by freed flag; calling close() on an already-freed handle is a no-op

### se.deversity.blindbean.fhe.FheContext.close()
- **Reason**: Guarded by closed flag; subsequent calls after first close() are no-ops

## Security-Critical Code

### se.deversity.blindbean.fhe.FheContext
- **Rule**: This code is security-critical. Do not weaken security properties. Every change must be explicitly reviewed for security impact.
- **Aspect**: fhe-encryption

## Security Audit Requirements

### se.deversity.blindbean.fhe.FheCiphertextNative
When modifying this element, audit for:
- Resource Leaks
- Memory Segment lifecycle
- Double-free
<!-- VIBETAGS-END -->
