<!-- VIBETAGS-START -->
# Rules for PaillierKeyPair

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

## Secure Logging Masking
- **Policy**: OMIT
- **Rule**: Never pass these raw variables to log appenders or stdout streams.
- **Applies to**: `PaillierKeyPair.lambda`, `PaillierKeyPair.mu`
<!-- VIBETAGS-END -->
