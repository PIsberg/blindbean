<!-- VIBETAGS-START -->
# Rules for FheCiphertextNative

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
