# Build and Test

> Extracted from `CLAUDE.md` so the always-loaded context stays small. Linked from the topic index there.

Builds on **JDK 26** (default) or **JDK 25**, with `--add-modules jdk.incubator.vector`. No `--enable-preview`: see `RUNTIME-FLAGS.md` for why it was removed and why 22 is the floor. The native DLL must be built before the Java tests that exercise FHE will pass.

```bash
# 1. Build native SEAL bridge (one-time / when blindbean-fhe/src/main/native changes)
cmake -S blindbean-fhe/src/main/native -B build-native \
    -DCMAKE_TOOLCHAIN_FILE=<vcpkg-root>/scripts/buildsystems/vcpkg.cmake \
    -DVCPKG_TARGET_TRIPLET=x64-windows-static
cmake --build build-native --config Release

# 2. Build + install Java library
./mvnw clean install -B -Dblindbean.native.path=build-native

# 3. Run tests
./mvnw clean test -Dblindbean.native.path=build-native

# Single test / single method
./mvnw test -Dtest=FheNativeBridgeTest -Dblindbean.native.path=build-native
./mvnw test -Dtest=FheContextTest#guidanceEchoesTheConfiguredPathWhenSet -Dblindbean.native.path=build-native

# JMH benchmarks
./mvnw clean verify
java --add-modules jdk.incubator.vector -jar target/benchmarks.jar
```

On Windows use `mvnw.cmd` and `-Dblindbean.native.path=build-native/Release` (MSVC puts artifacts under the config subdir; non-Windows builds do not). `JAVA_HOME` must point at a JDK 25 or 26 install — if it points at an older one, surefire forks that JVM and the run dies on a "class file version" error. To build at the lower level explicitly (what the CI matrix's 25 leg does), add `-Dmaven.compiler.release=25`.

The `blindbean-example` module is a separate Maven project demonstrating consumer usage of `@Homomorphic` / `@BlindEntity` and the generated wrappers — build the main library with `install` first so the example can resolve it.

Tests that touch BFV/CKKS need the native library; pure-Paillier, processor and JUnit-extension tests do not. Consumer-style tests should use `@BlindBeanTest` (below) rather than hand-rolling context setup.
