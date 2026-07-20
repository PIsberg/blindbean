cmake_minimum_required(VERSION 3.21...3.31)
project(blindbean_fhe LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# ── Optional AddressSanitizer + UndefinedBehaviorSanitizer build (GCC/Clang; CI memory-safety job) ──
option(BLINDBEAN_SANITIZE "Instrument the bridge with ASan + UBSan (GCC/Clang only)" OFF)

# ── Use Static C Runtime (CRT) on Windows ──
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

# ── Locate Microsoft SEAL (installed via vcpkg or system) ──
find_package(SEAL 4.3 REQUIRED)

# ── Build the shared library ──
add_library(blindbean_fhe SHARED blindbean_fhe.cpp)
target_compile_definitions(blindbean_fhe PRIVATE BLINDBEAN_EXPORTS)

target_link_libraries(blindbean_fhe PRIVATE SEAL::seal)

# Instrument the bridge (not SEAL) so ASan/UBSan flag use-after-free, double-free, heap overflows
# and undefined behaviour at the FFM boundary. The sanitizer interceptors are global, so heap
# errors crossing into the uninstrumented SEAL are still caught; UBSan covers our own sources. The
# JVM that loads the .so is not instrumented, so the CI job LD_PRELOADs the ASan runtime.
if(BLINDBEAN_SANITIZE)
    if(MSVC)
        message(FATAL_ERROR "BLINDBEAN_SANITIZE requires GCC or Clang")
    endif()
    # -shared-libasan: reference the dynamic ASan runtime (libasan.so) rather than static-linking it
    # into the .so, so the JVM can LD_PRELOAD the same runtime when it dlopens this library.
    target_compile_options(blindbean_fhe PRIVATE
        -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer -shared-libasan)
    target_link_options(blindbean_fhe PRIVATE -fsanitize=address,undefined -shared-libasan)
endif()

# On Windows the DLL is placed next to the import lib by default.
# Ensure a clean output name without "lib" prefix on all platforms.
set_target_properties(blindbean_fhe PROPERTIES
    PREFIX ""
    OUTPUT_NAME "blindbean_fhe"
)

# ── Installation (optional — useful for packaging) ──
install(TARGETS blindbean_fhe
    RUNTIME DESTINATION bin       # .dll on Windows
    LIBRARY DESTINATION lib       # .so on Linux / .dylib on macOS
)
install(FILES blindbean_fhe.h DESTINATION include)
