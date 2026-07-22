---
paths: ["**/fhe/*.java"]
---

<!-- VIBETAGS-START -->
# Rules for fhe-native-bridge

## se.deversity.blindbean.fhe.FheNativeBridge

## Locked Status
- **Reason**: Direct Memory FFM JNI mapping. Avoid breaking SEAL bridge architecture.

## Core Functionality
- **Sensitivity**: High
- **Note**: Well-tested core functionality. Make changes with extreme caution.

## se.deversity.blindbean.fhe.FheContext

### Rules for method initNative
- **Focus**: Every native context entry point must be routed through this helper so the missing-library failure — the first error most new users hit — stays actionable
- **Avoid**: Calling FheNativeBridge init symbols directly from a factory, which would surface a bare UnsatisfiedLinkError with no remediation guidance

## Core Functionality
- **Sensitivity**: High
- **Note**: Well-tested core functionality. Make changes with extreme caution.

### Rules for method encryptLongArray
- **Rule**: Optimal complexity required. O(n^2) is forbidden on hot paths.
- **Constraint**: Strict time/space complexity constraints apply. Suboptimal complexity is unacceptable.

### Rules for method multiply
- **Rule**: Optimal complexity required. O(n^2) is forbidden on hot paths.
- **Constraint**: Strict time/space complexity constraints apply. Suboptimal complexity is unacceptable.

## Contract-Frozen Signature
- **Constraint**: You may change internal logic, but MUST NOT modify the method name, parameters, return type, or checked exceptions.
- **Reason**: Public FHE API consumed by generated BlindWrapper classes; any signature change requires processor regeneration and a major version bump

## Test-Driven Requirements
- **Rule**: Changes MUST be accompanied by a matching test update.
- **Coverage Goal**: 90%
- **Frameworks**: JUNIT_5
- **Test Location**: src/test/java/se.deversity.blindbean/fhe

## Thread-Safety Guarantee
- **Strategy**: SYNCHRONIZED
- **Note**: All native FFM operations are guarded by nativeLock to prevent concurrent SEAL context access

### Rules for method noiseBudget
- **Rule**: Do not remove or rename instrumentation without flagging the affected dashboard.
- **Details**: Metrics: fhe.noise_budget. Note: Noise budget drives correctness alerts — dashboards fire when budget drops below safe threshold; do not remove or rename this method

### Rules for method initNative
- **Rule**: Robust exception handling required. Prohibit catching/throwing generic Exception/Throwable. Use descriptive, specific/custom exceptions.

### Rules for method close
- **Rule**: This operation is idempotent. Calling it multiple times must produce the same result as calling it once.
- **Reason**: Guarded by closed flag; subsequent calls after first close() are no-ops

## Security-Critical Code
- **Rule**: This code is security-critical. Do not weaken security properties. Every change must be explicitly reviewed for security impact.
- **Aspect**: fhe-encryption

## se.deversity.blindbean.fhe.FheCiphertextNative

## Security Audit Requirements
When modifying this element, audit for:
- Resource Leaks
- Memory Segment lifecycle
- Double-free

## Contract-Frozen Signature
- **Constraint**: You may change internal logic, but MUST NOT modify the method name, parameters, return type, or checked exceptions.
- **Reason**: Serialization format and handle lifecycle are part of the public FFM contract; do not change method signatures

## Strict Exception Handling
- **Rule**: Robust exception handling required. Prohibit catching/throwing generic Exception/Throwable. Use descriptive, specific/custom exceptions.

### Rules for method close
- **Rule**: This operation is idempotent. Calling it multiple times must produce the same result as calling it once.
- **Reason**: Guarded by freed flag; calling close() on an already-freed handle is a no-op
<!-- VIBETAGS-END -->
