<!-- VIBETAGS-START -->
# Rules for BlindMath

## Architectural Boundary Constraints
- **Layer**: math-layer
- **Prohibited References**: se.deversity.blindbean.fhe.FheNativeBridge

## Public API Surface Protection
- **Rule**: Exposes public API. Preserve signature, Javadoc, and behavior without breaking backwards or source compatibility.

## Strict Type Safety
- **Rule**: Loose typing (e.g., Object, raw types, generic Map<String, Object>) is strictly prohibited. Enforce type safety.
<!-- VIBETAGS-END -->
