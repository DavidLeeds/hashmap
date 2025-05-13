# Hashmap example
add_executable(hashmap_example hashmap_example.c)
target_compile_options(hashmap_example PRIVATE -Wall -Werror)
target_link_libraries(hashmap_example PRIVATE HashMap::HashMap)

