---
paths: ["**/core/*.java"]
---

<!-- VIBETAGS-START -->
# Rules for core-domain

## Immutable Type

### se.deversity.blindbean.core.Ciphertext
- **Rule**: This type is immutable. Never introduce non-final fields, setters, or mutating methods.
- **Note**: Java record — hexData and scheme are final record components; do not convert to a mutable class

## Public API Surface Protection

### se.deversity.blindbean.core.Ciphertext
- **Rule**: Exposes public API. Preserve signature, Javadoc, and behavior without breaking backwards or source compatibility.

## Schema & Serialization Safety

### se.deversity.blindbean.core.Ciphertext
- **Rule**: Prohibit altering data formats, fields, database columns, or serialization structures without explicit backward-compatible migration paths.

## Domain Model Boundary

### se.deversity.blindbean.core.Ciphertext
- **Purity**: Framework-free DDD Entity.
- **Allowed Imports**: se.deversity.blindbean.annotations.Scheme
<!-- VIBETAGS-END -->
