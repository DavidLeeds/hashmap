cmake_minimum_required(VERSION 3.19)
project(hashmap_test)

if(NOT DEFINED CMAKE_C_STANDARD)
    set(CMAKE_C_STANDARD 23)
    set(CMAKE_C_EXTENSIONS OFF)
endif()

if(NOT DEFINED CMAKE_CXX_STANDARD)
    set(CMAKE_CXX_STANDARD 20)
endif()

include(FetchContent)

# Fetch Catch2 unit test framework at configure time
FetchContent_Declare(
    Catch2
    GIT_REPOSITORY https://github.com/catchorg/Catch2.git
    GIT_TAG v3.8.1
    GIT_SHALLOW ON
)
FetchContent_MakeAvailable(Catch2)
list(APPEND CMAKE_MODULE_PATH ${catch2_SOURCE_DIR}/extras)
include(CTest)
include(Catch)

# Fetch Sanitizer CMake helpers
FetchContent_Declare(
    SanitizersCMake
    GIT_REPOSITORY https://github.com/arsenm/sanitizers-cmake.git
    GIT_SHALLOW ON
)
FetchContent_GetProperties(SanitizersCMake)
if(NOT SanitizersCMake_POPULATED)
    FetchContent_Populate(SanitizersCMake)
    list(APPEND CMAKE_MODULE_PATH ${sanitizerscmake_SOURCE_DIR}/cmake)
endif()

# Enable ASan and UBSan
find_package(Sanitizers)
set(SANITIZE_ADDRESS TRUE)
set(SANITIZE_UNDEFINED TRUE)

# Hashmap unit test
add_executable(hashmap_test hashmap_test.cpp)
target_compile_options(hashmap_test PRIVATE -Wall -Werror)
target_link_libraries(hashmap_test PRIVATE Catch2::Catch2WithMain HashMap::HashMap)
add_sanitizers(hashmap_test)
catch_discover_tests(hashmap_test)
