<!-- VIBETAGS-START -->
# Rules for PaillierMath

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
<!-- VIBETAGS-END -->
