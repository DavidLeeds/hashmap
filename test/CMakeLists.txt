cmake_minimum_required(VERSION 2.8)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wunused -Werror")

# Build hashmap library with metrics enabled
add_definitions(-DHASHMAP_METRICS)

include_directories(../src)

add_executable(hashmap_test ../src/hashmap.c hashmap_test.c)
