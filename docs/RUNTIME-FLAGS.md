# Runtime Flags

> Extracted from `CLAUDE.md` so the always-loaded context stays small. Linked from the topic index there.

Every `java`/`surefire` invocation against this codebase needs, at minimum:

```
--add-modules jdk.incubator.vector
--enable-native-access=ALL-UNNAMED
```

These are already wired into `maven-compiler-plugin` and `maven-surefire-plugin` in `pom.xml`. When running the JMH jar or the example module directly, pass them on the command line.

`--enable-preview` used to be on this list and is no longer needed anywhere. Nothing in the tree uses a preview language or API feature, and preview-compiled class files load on exactly one JDK — the one that produced them — which is what kept the published jar pinned to a single release and made a multi-JDK CI matrix impossible. Do not add it back without a preview feature that actually requires it.

`jdk.incubator.vector` stays: `PaillierVectorized` uses the Vector API, which is still an incubating module. That is why compiling emits a "using incubating module(s): jdk.incubator.vector" warning, and why `blindbean-runtime`'s `module-info` has `requires jdk.incubator.vector`.

## Supported JDKs

26 by default, 25 also supported, both covered by the CI matrix on Linux, macOS and Windows. The compile level is `${maven.compiler.release}` in `pom.xml`, so `./mvnw verify -Dmaven.compiler.release=25` reproduces the 25 leg locally.

The floor is **22**, not 21. `java.lang.foreign` (`Arena`, `MemorySegment`, `ValueLayout`, used throughout `blindbean-fhe`) was a preview API in 21, and `Arena.allocateFrom` did not exist there at all. Supporting 21 would be a rewrite of the FFM bridge, not a flag change.

The native library location is controlled by the `blindbean.native.path` system property (read by `FheNativeBridge` when loading symbols). Tests will fail fast if the DLL cannot be found there.
