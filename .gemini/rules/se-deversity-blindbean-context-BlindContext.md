<!-- VIBETAGS-START -->
# Rules for BlindContext

## Security Audit Requirements
When modifying this element, audit for:
- Resource Leaks
- Thread Safety
- Context Closure failures

## Core Functionality
- **Sensitivity**: High
- **Note**: Well-tested core functionality. Make changes with extreme caution.

## Test-Driven Requirements
- **Rule**: Changes MUST be accompanied by a matching test update.
- **Coverage Goal**: 90%
- **Frameworks**: JUNIT_5
- **Test Location**: src/test/java/se.deversity.blindbean/context

## Thread-Safety Guarantee
- **Strategy**: THREAD_LOCAL
- **Note**: Paillier and FHE state isolated in ThreadLocal fields; snapshot()/restore() required to propagate across virtual-thread boundaries

## Public API Surface Protection
- **Rule**: Exposes public API. Preserve signature, Javadoc, and behavior without breaking backwards or source compatibility.

### Rules for method clear
- **Rule**: This operation is idempotent. Calling it multiple times must produce the same result as calling it once.
- **Reason**: ThreadLocal.remove() and FheContext.close() are both safe to call when no state is present

## Security-Critical Code
- **Rule**: This code is security-critical. Do not weaken security properties. Every change must be explicitly reviewed for security impact.

### Rules for class BlindContext
- **Aspect**: key-management

### Rules for method exportKeys
- **Aspect**: key-serialization

### Rules for method loadKeys
- **Aspect**: key-deserialization

## Input Sanitization
- **Target Filters**: PATH_TRAVERSAL
- **Rule**: Run raw input strings through approved sanitizers.
- **Applies to**: `BlindContext.exportKeys(java.lang.String)#filePath`, `BlindContext.loadKeys(java.lang.String)#filePath`
<!-- VIBETAGS-END -->
