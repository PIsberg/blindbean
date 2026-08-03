<!-- VIBETAGS-START -->
# Rules for KeyBundle

### Rules for field serialVersionUID
- **Reason**: Serialization UID — altering this invalidates all persisted key bundles and breaks key import/export across versions

## PII / Privacy Guardrails
- **Rule**: Never log or expose runtime values of this element.
- **Reason**: Contains serialized Paillier private key material and SEAL key bytes — never log, transmit in plaintext, or expose field values in suggestions or test fixtures

## Schema & Serialization Safety
- **Rule**: Prohibit altering data formats, fields, database columns, or serialization structures without explicit backward-compatible migration paths.

## Access Restrictions
- **Allowed Callers**: [se.deversity.blindbean.context.BlindContext]

## Secure Logging Masking
- **Policy**: OMIT
- **Rule**: Never pass these raw variables to log appenders or stdout streams.
- **Applies to**: `KeyBundle.nativeFhePayload`, `KeyBundle.paillierKeyPair`
<!-- VIBETAGS-END -->
