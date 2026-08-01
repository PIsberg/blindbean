---
paths: ["**/math/*.java"]
---

<!-- VIBETAGS-START -->
# Rules for paillier-and-math

## Locked Status

### se.deversity.blindbean.math.PaillierKeyPair.serialVersionUID
- **Reason**: Serialization UID — changing this breaks deserialization of persisted KeyBundle files

## PII / Privacy Guardrails

### se.deversity.blindbean.math.PaillierKeyPair
- **Rule**: Never log or expose runtime values of this element.
- **Reason**: Contains RSA-family private key components (lambda, mu) — never log values, include in test fixtures, or expose in suggestions

## Immutable Type

### se.deversity.blindbean.math.PaillierKeyPair
- **Rule**: This type is immutable. Never introduce non-final fields, setters, or mutating methods.
- **Note**: All key material is computed once in the constructor and stored in final fields; never add setters, non-final fields, or post-construction mutation

## Schema & Serialization Safety

### se.deversity.blindbean.math.PaillierKeyPair
- **Rule**: Prohibit altering data formats, fields, database columns, or serialization structures without explicit backward-compatible migration paths.

## Security-Critical Code
- **Rule**: This code is security-critical. Do not weaken security properties. Every change must be explicitly reviewed for security impact.

### se.deversity.blindbean.math.PaillierKeyPair
- **Aspect**: key-generation

### se.deversity.blindbean.math.PaillierMath
- **Aspect**: paillier-encryption

## Secure Logging Masking
- **Policy**: OMIT
- **Rule**: Never pass these raw variables to log appenders or stdout streams.
- **Applies to**: `se.deversity.blindbean.math.PaillierKeyPair.lambda`, `se.deversity.blindbean.math.PaillierKeyPair.mu`

## Performance Constraints
- **Rule**: Optimal complexity required. O(n^2) is forbidden on hot paths.

### se.deversity.blindbean.math.PaillierMath
- **Constraint**: Encryption/decryption are modPow-heavy over large BigIntegers — never introduce extra copies, unnecessary allocations, or redundant modular reductions on the hot path

### se.deversity.blindbean.math.PaillierVectorized
- **Constraint**: Strict time/space complexity constraints apply. Suboptimal complexity is unacceptable.

### se.deversity.blindbean.math.PaillierVectorized.batchAddBigInteger(java.math.BigInteger[],java.math.BigInteger[],java.math.BigInteger)
- **Constraint**: Strict time/space complexity constraints apply. Suboptimal complexity is unacceptable.

## Strict Exception Handling

### se.deversity.blindbean.math.PaillierMath
- **Rule**: Robust exception handling required. Prohibit catching/throwing generic Exception/Throwable. Use descriptive, specific/custom exceptions.

## Chain-of-Thought Explanation
- **Complexity Level**: HIGH
- **Rule**: Any logic modification requires updating a walkthrough/markdown file with structured architectural rationale.
- **Applies to**: `se.deversity.blindbean.math.PaillierMath`, `se.deversity.blindbean.math.PaillierVectorized.batchAdd(long[],long[],long[],long)`

## Thread-Safety Guarantee

### se.deversity.blindbean.math.PaillierVectorized
- **Strategy**: IMMUTABLE
- **Note**: Stateless utility class — SPECIES is a compile-time constant; no instance state

## Memory Budget Constraints

### se.deversity.blindbean.math.PaillierVectorized.batchAdd(long[],long[],long[],long)
- **Policy**: NO_AUTOBOXING
- **Rule**: Strictly limit or prevent object allocations.

## Mathematical Purity

### se.deversity.blindbean.math.PaillierVectorized.batchAddBigInteger(java.math.BigInteger[],java.math.BigInteger[],java.math.BigInteger)
- **Rule**: Must remain a pure function. Forbid state modifications and side effects.

## Architectural Boundary Constraints

### se.deversity.blindbean.math.BlindMath
- **Layer**: math-layer
- **Prohibited References**: se.deversity.blindbean.fhe.FheNativeBridge

## Public API Surface Protection

### se.deversity.blindbean.math.BlindMath
- **Rule**: Exposes public API. Preserve signature, Javadoc, and behavior without breaking backwards or source compatibility.

## Strict Type Safety

### se.deversity.blindbean.math.BlindMath
- **Rule**: Loose typing (e.g., Object, raw types, generic Map<String, Object>) is strictly prohibited. Enforce type safety.
<!-- VIBETAGS-END -->
