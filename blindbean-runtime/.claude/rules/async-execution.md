---
paths: ["**/async/*.java"]
---

<!-- VIBETAGS-START -->
# Rules for async-execution

## Exclusion Rule

### se.deversity.blindbean.async.BlindAsync.INIT_LOCK
This element is strictly excluded from AI context. Do not reference it.
- **Reason**: Internal DCL synchronization monitor — not relevant to AI-assisted development workflows

## Security Audit Requirements

### se.deversity.blindbean.async.BlindAsync
When modifying this element, audit for:
- Thread Safety
- Resource Leaks
- Shutdown race conditions

## Thread-Safety Guarantee

### se.deversity.blindbean.async.BlindAsync
- **Strategy**: OTHER
- **Note**: Executor + semaphore held as one immutable State behind a single volatile (DCL lazy init); CPU-bound semaphore serializes FHE tasks across virtual threads; shutdown races resolved by re-submitting under the init monitor, which shutdown() must also acquire

## Strict Test Isolation

### se.deversity.blindbean.async.BlindAsync
- **Rule**: Strict test isolation required. AI-generated or modified tests must not share mutable state, rely on execution order, or conflict on external resources.

## Feature Flag Gate

### se.deversity.blindbean.async.BlindAsync
- **Flag**: 'blindbean.apt.async' (default: false)
- **Rule**: This code is gated behind a feature flag. Preserve the flag check. Never assume the flag is always active.
<!-- VIBETAGS-END -->
