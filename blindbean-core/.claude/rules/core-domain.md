---
paths: ["**/core/*.java"]
---

<!-- VIBETAGS-START -->
# Rules for core-domain

## se.deversity.blindbean.core.Ciphertext

## Immutable Type
- **Rule**: This type is immutable. Never introduce non-final fields, setters, or mutating methods.
- **Note**: Java record — hexData and scheme are final record components; do not convert to a mutable class

## Public API Surface Protection
- **Rule**: Exposes public API. Preserve signature, Javadoc, and behavior without breaking backwards or source compatibility.

## Schema & Serialization Safety
- **Rule**: Prohibit altering data formats, fields, database columns, or serialization structures without explicit backward-compatible migration paths.

## Domain Model Boundary
- **Purity**: Framework-free DDD Entity.
- **Allowed Imports**: se.deversity.blindbean.annotations.Scheme
<!-- VIBETAGS-END -->
