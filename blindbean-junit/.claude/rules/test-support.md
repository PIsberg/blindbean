---
paths: ["**/junit/*.java"]
---

<!-- VIBETAGS-START -->
# Rules for test-support

## Contract-Frozen Signature

### se.deversity.blindbean.junit.BlindBeanExtension.beforeEach(org.junit.jupiter.api.extension.ExtensionContext)
- **Constraint**: You may change internal logic, but MUST NOT modify the method name, parameters, return type, or checked exceptions.
- **Reason**: JUnit 5 BeforeEachCallback contract — signature is fixed by the framework SPI

## Test-Driven Requirements

### se.deversity.blindbean.junit.BlindBeanExtension
- **Rule**: Changes MUST be accompanied by a matching test update.
- **Coverage Goal**: 90%
- **Frameworks**: JUNIT_5
- **Test Location**: src/test/java/se.deversity.blindbean/junit

## Public API Surface Protection
- **Rule**: Exposes public API. Preserve signature, Javadoc, and behavior without breaking backwards or source compatibility.

### se.deversity.blindbean.junit.BlindBeanExtension
- **Reason**: Consumers reference this extension directly via @ExtendWith and inherit it through @BlindBeanTest; renaming or changing its callbacks breaks every downstream test suite

### se.deversity.blindbean.junit.BlindBeanTest
- **Reason**: Attribute names (scheme, polyModulusDegree, ckksScale) and their defaults are written into consumer test classes; renaming or removing one silently changes which context those suites boot

## Idempotency Guarantee

### se.deversity.blindbean.junit.BlindBeanExtension.afterEach(org.junit.jupiter.api.extension.ExtensionContext)
- **Rule**: This operation is idempotent. Calling it multiple times must produce the same result as calling it once.
- **Reason**: Cleanup must tolerate a failed/partial beforeEach and repeated invocation — BlindContext.clear() is itself idempotent; never make teardown conditional on setup having succeeded, or a failing test would leak keys and native handles into the next one
<!-- VIBETAGS-END -->
