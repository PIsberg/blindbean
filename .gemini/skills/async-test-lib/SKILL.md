**async-test-lib** is a JUnit 5 extension for stress-testing concurrent Java code. It forces real thread collisions using a `CyclicBarrier`, then runs 51+ specialized detectors to identify exactly what went wrong.

- Replaces `@Test` with `@AsyncTest` — zero other changes needed
- Requires Java 21 and JUnit 5 (Jupiter 6.0.3+)
- License: PolyForm Noncommercial (commercial use requires a separate license)

---

## Dependency
**Maven**
```xml
<dependency>
    <groupId>se.deversity.async-test-lib</groupId>
    <artifactId>async-test-lib</artifactId>
    <version>0.5.0</version>
    <scope>test</scope>
</dependency>
```

**Gradle (Kotlin DSL)**
```kotlin
testImplementation("se.deversity.async-test-lib:async-test-lib:0.5.0")
```

---

## Quickstart
```java
import com.github.asynctest.AsyncTest;

class CounterTest {

    private int counter = 0; // BUG: not thread-safe

    @AsyncTest(threads = 10, invocations = 100, detectAll = true)
    void increment() {
        counter++;            // Caught: race condition / atomicity violation
    }
}
```

`@AsyncTest` launches `threads` concurrent threads per invocation, repeats `invocations` times, and reports exactly which detector fired and why. The same test with plain `@Test` would pass silently.

---

## @AsyncTest — all parameters
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `threads` | int | 10 | Concurrent threads per invocation round |
| `invocations` | int | 100 | Number of invocation rounds |
| `useVirtualThreads` | boolean | true | Use Project Loom virtual threads (Java 21+) |
| `timeoutMs` | long | 5000 | Milliseconds before timeout (triggers deadlock analysis) |
| `virtualThreadStressMode` | String | `"OFF"` | `OFF` / `LOW` / `MEDIUM` / `HIGH` / `EXTREME` — pins carrier threads to increase contention |
| `detectAll` | boolean | false | Enable every detector at once |
| `excludes` | DetectorType[] | `{}` | Detectors to skip when `detectAll = true` |
| `detectDeadlocks` | boolean | true | Always-on deadlock detection |
| `detectVisibility` | boolean | false | Missing `volatile`, stale memory reads |
| `detectLivelocks` | boolean | false | Threads spinning without making progress |
| `detectRaceConditions` | boolean | false | Unsynchronized cross-thread field access |
| `detectAtomicityViolations` | boolean | false | Check-then-act patterns (e.g., `if (!map.containsKey(k)) map.put(k, v)`) |
| `detectBusyWaiting` | boolean | false | Tight spin loops |
| `detectThreadLocalLeaks` | boolean | false | Missing `ThreadLocal.remove()` |
| `detectInterruptMishandling` | boolean | false | Swallowed `InterruptedException` |
| `enableBenchmarking` | boolean | false | Record timing data for regression detection |
| `benchmarkRegressionThreshold` | double | 0.2 | Regression threshold as a decimal (0.2 = 20%) |
| `failOnBenchmarkRegression` | boolean | false | Fail the test if a regression is detected |

*Individual Phase 2 detectors (false sharing, ABA, lock order, CompletableFuture, etc.) can each be turned on independently — see the full list below.*

---

## Tips
- **Start with `detectAll = true`** to catch everything, then narrow to only the detectors you care about once you understand the failures.
- **Increase `invocations` before `threads`** — more rounds give detectors more chances to observe bad interleavings. 200–1000 invocations is a good baseline.
- **Use `@BeforeEachInvocation` to reset shared state** between rounds; not doing so causes round N's leftover state to pollute round N+1.
- **`timeoutMs`** controls how long a round can run before deadlock analysis fires. Lower it for tests that should complete quickly.
- **`virtualThreadStressMode = "HIGH"`** is the fastest way to reproduce virtual thread pinning bugs; leave it `OFF` for normal tests (it adds overhead).
- **Benchmark baselines** are per-machine, per-environment. Commit `target/benchmark-data/` to get stable CI regression detection, or use `-Dbenchmark.store.path` to point at a stable location outside `target/`.
