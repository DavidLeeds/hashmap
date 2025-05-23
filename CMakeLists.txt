cmake_minimum_required(VERSION 3.16)
project(hashmap VERSION 2.1.0 LANGUAGES C)

if(NOT DEFINED CMAKE_C_STANDARD)
    set(CMAKE_C_STANDARD 23)
    set(CMAKE_C_EXTENSIONS OFF)
endif()

##############################################
# Build options

option(HASHMAP_BUILD_TESTS "Build tests" OFF)
option(HASHMAP_BUILD_EXAMPLES "Build examples" OFF)

##############################################
# Set default build to release

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "Release" CACHE STRING "Choose Release or Debug" FORCE)
endif()

##############################################
# Create target and set properties

add_library(hashmap
    src/hashmap.c
)

# Add an alias so that library can be used inside the build tree,
# e.g. when testing
add_library(HashMap::HashMap ALIAS hashmap)

# Set target properties
target_include_directories(hashmap
    PUBLIC
        $<INSTALL_INTERFACE:include>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)
target_compile_options(hashmap
    PRIVATE -Wall -Werror
)

##############################################
# Installation instructions

include(GNUInstallDirs)
set(INSTALL_CONFIGDIR ${CMAKE_INSTALL_LIBDIR}/cmake/HashMap)

install(TARGETS hashmap
    EXPORT hashmap-targets
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

# Ensure the exported target has the name HashMap and not hashmap
# and if this is linked into a shared library, ensure it is PIC
set_target_properties(hashmap
    PROPERTIES
        EXPORT_NAME HashMap
        POSITION_INDEPENDENT_CODE ON
)

install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

# Export the targets to a script
install(EXPORT hashmap-targets
    FILE
        HashMapTargets.cmake
    NAMESPACE
        HashMap::
    DESTINATION
        ${INSTALL_CONFIGDIR}
)

# Create a ConfigVersion.cmake file
include(CMakePackageConfigHelpers)
write_basic_package_version_file(
    ${CMAKE_CURRENT_BINARY_DIR}/HashMapConfigVersion.cmake
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY AnyNewerVersion
)

configure_package_config_file(
    ${CMAKE_CURRENT_LIST_DIR}/cmake/HashMapConfig.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/HashMapConfig.cmake
    INSTALL_DESTINATION ${INSTALL_CONFIGDIR}
)

# Install the config, configversion and custom find modules
install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/HashMapConfig.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/HashMapConfigVersion.cmake
    DESTINATION ${INSTALL_CONFIGDIR}
)

##############################################
# Exporting from the build tree

export(EXPORT hashmap-targets
    FILE ${CMAKE_CURRENT_BINARY_DIR}/HashMapTargets.cmake
    NAMESPACE HashMap::
)

# Register package in user's package registry
export(PACKAGE HashMap)

##############################################
# Build unit test

if(HASHMAP_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

##############################################
# Build examples

if(HASHMAP_BUILD_EXAMPLES)
    add_subdirectory(examples)
endif()

