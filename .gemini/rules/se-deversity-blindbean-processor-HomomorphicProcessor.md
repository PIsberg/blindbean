<!-- VIBETAGS-START -->
# Rules for HomomorphicProcessor

## Context & Focus
- **Focus**: Strictly maintain high-performance AST compilation speed
- **Avoid**: Heavy internal object allocations

## Exclusion Rule
These elements are strictly excluded from AI context. Do not reference them.
- **Applies to**: `HomomorphicProcessor.getBoxedType(java.lang.String)`, `HomomorphicProcessor.getPrimitiveType(java.lang.String)`, `HomomorphicProcessor.isFloatingPoint(java.lang.String)`, `HomomorphicProcessor.isIntegral(java.lang.String)`

## Internationalization Mandate
- **Rule**: Prohibit hardcoding user-facing strings, labels, or messages. All user-visible text must be resolved via localization resources.

## Strict Classpath Integrity
- **Rule**: Prohibit dynamic class loading, custom classloaders, runtime reflection hacks, or execution of dynamic external code.

### Rules for method generateBlindWrapper
- **Flag**: 'blindbean.apt.async' (default: false)
- **Rule**: This code is gated behind a feature flag. Preserve the flag check. Never assume the flag is always active.
<!-- VIBETAGS-END -->
