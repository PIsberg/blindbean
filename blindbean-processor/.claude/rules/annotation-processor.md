---
paths: ["**/processor/*.java"]
---

<!-- VIBETAGS-START -->
# Rules for annotation-processor

## Context & Focus

### se.deversity.blindbean.processor.HomomorphicProcessor
- **Focus**: Strictly maintain high-performance AST compilation speed
- **Avoid**: Heavy internal object allocations

## Exclusion Rule
These elements are strictly excluded from AI context. Do not reference them.

### se.deversity.blindbean.processor.HomomorphicProcessor.getBoxedType(java.lang.String)
- **Reason**: Pure internal type-mapping helper — not part of the public processor API

### se.deversity.blindbean.processor.HomomorphicProcessor.getPrimitiveType(java.lang.String)
- **Reason**: Pure internal type-mapping helper — not part of the public processor API

### se.deversity.blindbean.processor.HomomorphicProcessor.isFloatingPoint(java.lang.String)
- **Reason**: Pure internal type-dispatch helper — not part of the public processor API

### se.deversity.blindbean.processor.HomomorphicProcessor.isIntegral(java.lang.String)
- **Reason**: Pure internal type-dispatch helper — not part of the public processor API

## Internationalization Mandate

### se.deversity.blindbean.processor.HomomorphicProcessor
- **Rule**: Prohibit hardcoding user-facing strings, labels, or messages. All user-visible text must be resolved via localization resources.

## Strict Classpath Integrity

### se.deversity.blindbean.processor.HomomorphicProcessor
- **Rule**: Prohibit dynamic class loading, custom classloaders, runtime reflection hacks, or execution of dynamic external code.

## Feature Flag Gate

### se.deversity.blindbean.processor.HomomorphicProcessor.generateBlindWrapper(java.lang.String,java.lang.String,javax.lang.model.element.TypeElement,java.util.List<se.deversity.blindbean.processor.HomomorphicProcessor.FieldModel>,java.util.List<se.deversity.blindbean.processor.HomomorphicProcessor.NestedModel>)
- **Flag**: 'blindbean.apt.async' (default: false)
- **Rule**: This code is gated behind a feature flag. Preserve the flag check. Never assume the flag is always active.
<!-- VIBETAGS-END -->
