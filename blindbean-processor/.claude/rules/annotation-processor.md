---
paths: ["**/processor/*.java"]
---

<!-- VIBETAGS-START -->
# Rules for annotation-processor

## se.deversity.blindbean.processor.HomomorphicProcessor

## Context & Focus
- **Focus**: Strictly maintain high-performance AST compilation speed
- **Avoid**: Heavy internal object allocations

### Rules for method isIntegral
This element is strictly excluded from AI context. Do not reference it.

### Rules for method isFloatingPoint
This element is strictly excluded from AI context. Do not reference it.

### Rules for method getPrimitiveType
This element is strictly excluded from AI context. Do not reference it.

### Rules for method getBoxedType
This element is strictly excluded from AI context. Do not reference it.

## Internationalization Mandate
- **Rule**: Prohibit hardcoding user-facing strings, labels, or messages. All user-visible text must be resolved via localization resources.

## Strict Classpath Integrity
- **Rule**: Prohibit dynamic class loading, custom classloaders, runtime reflection hacks, or execution of dynamic external code.

### Rules for method generateBlindWrapper
- **Flag**: 'blindbean.apt.async' (default: false)
- **Rule**: This code is gated behind a feature flag. Preserve the flag check. Never assume the flag is always active.
<!-- VIBETAGS-END -->
