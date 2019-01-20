cmake_minimum_required(VERSION 2.8)

project(hashmap)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wunused -Werror")

file(GLOB SOURCES src/*.c)

# Static library build option
option(HASHMAP_STATIC_LIB "Build static libhashmap" OFF)

if(HASHMAP_STATIC_LIB)
    # Static library
    add_library(${PROJECT_NAME} STATIC ${SOURCES})
else()
    # Shared library
    add_library(${PROJECT_NAME} SHARED ${SOURCES})
endif()

target_include_directories(${PROJECT_NAME} PUBLIC src)
