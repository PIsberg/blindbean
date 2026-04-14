cmake_minimum_required(VERSION 3.21...3.31)
project(blindbean_fhe LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# ── Locate Microsoft SEAL (installed via vcpkg or system) ──
find_package(SEAL 4.1 REQUIRED)

# ── Build the shared library ──
add_library(blindbean_fhe SHARED blindbean_fhe.cpp)

target_link_libraries(blindbean_fhe PRIVATE SEAL::seal)

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
