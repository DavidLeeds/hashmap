cmake_minimum_required(VERSION 3.5)

# Hashmap unit test
add_executable(hashmap_test hashmap_test.c)
target_compile_options(hashmap_test PRIVATE $<$<C_COMPILER_ID:GNU>:-Wall -Werror>)
target_link_libraries(hashmap_test PRIVATE HashMap::HashMap)

# Register with CTest
add_test(NAME hashmap_test COMMAND hashmap_test)

