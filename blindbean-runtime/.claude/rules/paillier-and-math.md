---
paths: ["**/math/*.java"]
---

<!-- VIBETAGS-START -->
# Rules for paillier-and-math

## se.deversity.blindbean.math.PaillierKeyPair

### Rules for field serialVersionUID
- **Reason**: Serialization UID — changing this breaks deserialization of persisted KeyBundle files

## PII / Privacy Guardrails
- **Rule**: Never log or expose runtime values of this element.
- **Reason**: Contains RSA-family private key components (lambda, mu) — never log values, include in test fixtures, or expose in suggestions

## Immutable Type
- **Rule**: This type is immutable. Never introduce non-final fields, setters, or mutating methods.
- **Note**: All key material is computed once in the constructor and stored in final fields; never add setters, non-final fields, or post-construction mutation

## Schema & Serialization Safety
- **Rule**: Prohibit altering data formats, fields, database columns, or serialization structures without explicit backward-compatible migration paths.

## Security-Critical Code
- **Rule**: This code is security-critical. Do not weaken security properties. Every change must be explicitly reviewed for security impact.
- **Aspect**: key-generation

### Rules for field lambda
- **Policy**: OMIT
- **Rule**: Never pass this raw variable to log appenders or stdout streams.

### Rules for field mu
- **Policy**: OMIT
- **Rule**: Never pass this raw variable to log appenders or stdout streams.

## se.deversity.blindbean.math.PaillierMath

## Performance Constraints
- **Rule**: Optimal complexity required. O(n^2) is forbidden on hot paths.
- **Constraint**: Encryption/decryption are modPow-heavy over large BigIntegers — never introduce extra copies, unnecessary allocations, or redundant modular reductions on the hot path

## Strict Exception Handling
- **Rule**: Robust exception handling required. Prohibit catching/throwing generic Exception/Throwable. Use descriptive, specific/custom exceptions.

## Security-Critical Code
- **Rule**: This code is security-critical. Do not weaken security properties. Every change must be explicitly reviewed for security impact.
- **Aspect**: paillier-encryption

## Chain-of-Thought Explanation
- **Complexity Level**: HIGH
- **Rule**: Any logic modification requires updating a walkthrough/markdown file with structured architectural rationale.

## se.deversity.blindbean.math.PaillierVectorized

## Performance Constraints
- **Rule**: Optimal complexity required. O(n^2) is forbidden on hot paths.
- **Constraint**: Strict time/space complexity constraints apply. Suboptimal complexity is unacceptable.

### Rules for method batchAddBigInteger
- **Rule**: Optimal complexity required. O(n^2) is forbidden on hot paths.
- **Constraint**: Strict time/space complexity constraints apply. Suboptimal complexity is unacceptable.

## Thread-Safety Guarantee
- **Strategy**: IMMUTABLE
- **Note**: Stateless utility class — SPECIES is a compile-time constant; no instance state

### Rules for method batchAdd
- **Policy**: NO_AUTOBOXING
- **Rule**: Strictly limit or prevent object allocations.

### Rules for method batchAddBigInteger
- **Rule**: Must remain a pure function. Forbid state modifications and side effects.

### Rules for method batchAdd
- **Complexity Level**: HIGH
- **Rule**: Any logic modification requires updating a walkthrough/markdown file with structured architectural rationale.

## se.deversity.blindbean.math.BlindMath

## Architectural Boundary Constraints
- **Layer**: math-layer
- **Prohibited References**: se.deversity.blindbean.fhe.FheNativeBridge

## Public API Surface Protection
- **Rule**: Exposes public API. Preserve signature, Javadoc, and behavior without breaking backwards or source compatibility.

## Strict Type Safety
- **Rule**: Loose typing (e.g., Object, raw types, generic Map<String, Object>) is strictly prohibited. Enforce type safety.
<!-- VIBETAGS-END -->
