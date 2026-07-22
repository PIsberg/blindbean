---
paths: ["**/junit/*.java"]
---

<!-- VIBETAGS-START -->
# Rules for test-support

## se.deversity.blindbean.junit.BlindBeanExtension

### Rules for method beforeEach
- **Constraint**: You may change internal logic, but MUST NOT modify the method name, parameters, return type, or checked exceptions.
- **Reason**: JUnit 5 BeforeEachCallback contract — signature is fixed by the framework SPI

## Test-Driven Requirements
- **Rule**: Changes MUST be accompanied by a matching test update.
- **Coverage Goal**: 90%
- **Frameworks**: JUNIT_5
- **Test Location**: src/test/java/se.deversity.blindbean/junit

## Public API Surface Protection
- **Rule**: Exposes public API. Preserve signature, Javadoc, and behavior without breaking backwards or source compatibility.

### Rules for method afterEach
- **Rule**: This operation is idempotent. Calling it multiple times must produce the same result as calling it once.
- **Reason**: Cleanup must tolerate a failed/partial beforeEach and repeated invocation — BlindContext.clear() is itself idempotent; never make teardown conditional on setup having succeeded, or a failing test would leak keys and native handles into the next one

## se.deversity.blindbean.junit.BlindBeanTest

## Public API Surface Protection
- **Rule**: Exposes public API. Preserve signature, Javadoc, and behavior without breaking backwards or source compatibility.
<!-- VIBETAGS-END -->
