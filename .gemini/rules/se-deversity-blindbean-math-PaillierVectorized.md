<!-- VIBETAGS-START -->
# Rules for PaillierVectorized

## Performance Constraints
- **Rule**: Optimal complexity required. O(n^2) is forbidden on hot paths.
- **Constraint**: Strict time/space complexity constraints apply. Suboptimal complexity is unacceptable.
- **Applies to**: `PaillierVectorized`, `PaillierVectorized.batchAddBigInteger(java.math.BigInteger[],java.math.BigInteger[],java.math.BigInteger)`

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
<!-- VIBETAGS-END -->
