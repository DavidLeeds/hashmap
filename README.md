# hashmap

[![ci](https://github.com/DavidLeeds/hashmap/workflows/CI/badge.svg)](https://github.com/DavidLeeds/hashmap/actions/workflows/ci.yml)

Templated type-safe hashmap implementation in C using open addressing and linear probing for collision resolution.

## Summary

This project came into existence because there are a notable lack of flexible and easy to use data structures available in C. C data structures with efficient, type-safe interfaces are virtually non-existent.  Higher level languages have built-in libraries and templated classes, but plenty of embedded projects or higher level libraries are implemented in C.  When it is undesireable to depend on a bulky library like Glib or grapple with a restrictive license agreement, this is the library for you.

## Goals

* **To scale gracefully to the full capacity of the numeric primitives in use.**  We should be able to load enough entries to consume all memory on the system without hitting any bugs relating to integer overflows.  Lookups on a hashtable with a hundreds of millions of entries should be performed in close to constant time, no different than lookups in a hashtable with 20 entries.  Automatic rehashing occurs and maintains a load factor of 0.75 or less.
* **To provide a clean and easy-to-use interface.**  C data structures often struggle to strike a balance between flexibility and ease of use.  To this end, I wrapped a generic C backend implementation with light-weight pre-processor macros to create a templated interface that enables the compiler to type-check all function arguments and return values. All required type information is encoded in the hashmap declaration using the`HASHMAP()` macro. Unlike with header-only macro libraries, there is no code duplication or performance disadvantage over a traditional library with a non-type-safe `void *` interface.
* **To enable easy iteration and safe entry removal during iteration.**  Applications often need these features, and the data structure should not hold them back.  Easy to use `hashmap_foreach()` macros and a more flexible iterator interface are provided.  This hashmap also uses an open addressing scheme, which has superior iteration performance to a similar hashmap implemented using separate chaining (buckets with linked lists).  This is because fewer instructions are needed per iteration, and array traversal has superior cache performance than linked list traversal.
* **To use an unrestrictive software license.**  I chose the MIT license because it is the most common open source license in use, and it grants full rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell the code.  Basically, take this code and do what you want with it.  Just be nice and leave the license comment and my name at top of the file.  Feel free to add your name as a contributor if you are significantly modifying and redistributing.

## API Examples

### Declaring a type-specific hashmap

Use the `HASHMAP(key_type, value_type)` macro to declare a hashmap state struct specific to your needs. Keys and values are always passed in by pointer. Keys are const.

```C
/* Map with string key (const char *) and integer value (int *) */
HASHMAP(char, int) map1;

/* Map with uint64 key (const uint64_t *) and struct value (struct my_value *) */
HASHMAP(uint64_t, struct my_value) map2;
```

The structure defined by the `HASHMAP()` macro may be used directly, or named using `typedef`. For example:

```C
typedef HASHMAP(char, struct my_value) value_map_t;
```

### Initialization and cleanup

Maps must be initialized with a key hash function and a key comparator.

```C
/* Initialize the map structure */
hashmap_init(&map, my_key_hash, my_key_compare);

/* Use the map... */

/* Free resources associated with the map */
hashmap_cleanup(&map);
```

This library provides some hash functions, so you may not have to write your own:

* [hashmap_hash_string()](https://github.com/DavidLeeds/hashmap/blob/137d60b3818c22c79d2be5560150eb2eff981a68/include/hashmap_base.h#L54) - Case sensitive string hash
* [hashmap_hash_string_i()](https://github.com/DavidLeeds/hashmap/blob/137d60b3818c22c79d2be5560150eb2eff981a68/include/hashmap_base.h#L55) - Case insensitive string hash
* [hashmap_hash_default()](https://github.com/DavidLeeds/hashmap/blob/137d60b3818c22c79d2be5560150eb2eff981a68/include/hashmap_base.h#L53) - Hash function for arbitrary bytes that can be used by a user-defined hash function

I recommend using these, unless you have very specific needs.

```C
/* Initialize a map with case-sensitive string keys */
hashmap_init(&map, hashmap_hash_string, strcmp);
```

Note that memory associated with map keys and values is not managed by the map, so you may need to free this before calling `hashmap_cleanup()`. Keys are often stored in the same structure as the value, but it is possible to have the map manage key memory allocation internally, by calling `hashmap_set_key_alloc_funcs()`.

### Value insertion

```C
struct my_value *val = /* ... */;

/* Add a my_value (fails and returns -EEXIST if the key already exists) */
int result1 = hashmap_put(&map, "KeyABC", val);

/* Add or update a my_value (assigns previous value to old_data if the key already exists) */
struct my_value *old_val;
int result2 = hashmap_insert(&map, "KeyABC", val, &old_val);
```

### Value access

```C
/* Access the value with a given key */
struct my_value *val1 = hashmap_get(&map, "KeyABC");

/* Access the key or value with an iterator */
HASHMAP_ITER(map) iter = hashmap_iter_find(&map, "keyABC");
const char *key = hashmap_iter_get_key(&iter);
struct my_value *val2 = hashmap_iter_get_data(&iter);

/* Check if an entry with the given key exists */
bool present = hashmap_contains(&map, "KeyABC");
```

### Value removal

```C
/* Erase the entry with the given key */
struct my_value *val = hashmap_remove(&map, "KeyABC");

/* Erase the entry with an iterator */
HASHMAP_ITER(map) iter = hashmap_iter_find(&map, "keyABC");
hashmap_iter_remove(&iter);

/* Erase all entries */
hashmap_clear(&map);

/* Erase all entries and reset the hash table heap allocation to its initial size */
hashmap_reset(&map);
```

### Iteration

Iteration may be accomplished using the "convenience" `foreach` macros, or by using the iterator interface directly. Generally, the `foreach` macros are the most intuitive and convenient.

```C
const char *key;
struct my_value *val;

/* Iterate over all map entries and access both keys and values */
hashmap_foreach(key, val, &map) {
    /* Access each entry */
}

/* Iterate over all map entries and access just keys */
hashmap_foreach_key(key, &map) {
    /* Access each entry */
}

/* Iterate over all map entries and access just values */
hashmap_foreach_data(val, &map) {
    /* Access each entry */
}
```

The above iteration macros are only safe for read-only access. To safely remove the current element during iteration, use the macros with a `_safe` suffix. These require an additional pointer parameter. For example:

```C
const char *key;
struct my_value *val;
void *pos;

/* Okay */
hashmap_foreach_key_safe(key, &map, pos) {
    hashmap_remove(&map, key);
}
```

Iteration using the iterator interface.

```C
HASHMAP_ITER(map) it;

for (it = hashmap_iter(&map); hashmap_iter_valid(&it); hashmap_iter_next(&it)) {
    /*
     * Access entry using:
     *   hashmap_iter_get_key()
     *   hashmap_iter_get_data()
     *   hashmap_iter_set_data()
     */
}
```

### Additional examples

Are located in the [examples](https://github.com/DavidLeeds/hashmap/tree/master/examples) directory in the source tree.

## How to Build and Install

This project uses CMake to orchestrate the build and installallation process.

### CMake Options

* `HASHMAP_BUILD_TESTS` - Set to `ON` to generate unit tests.
* `HASHMAP_BUILD_EXAMPLES` - Set to `ON` to build example code.

### How to build from source

To build and install on your host system, follow these easy steps:

1. `git clone https://github.com/DavidLeeds/hashmap.git` - download the source
2. `mkdir build-hashmap && cd build-hashmap` - create a build directory outside the source tree
3. `cmake ../hashmap` - run CMake to setup the build
4. `make` - compile the code
5. `make test` - run the unit tests (if enabled)
6. `sudo make install` - _OPTIONAL_ install the library on this system

### How to integrate with an existing CMake project

Clone and build this repository:

```cmake
include(FetchContent)

FetchContent_Declare(
    hashmap
    GIT_REPOSITORY https://github.com/DavidLeeds/hashmap.git
    GIT_SHALLOW ON
)
FetchContent_MakeAvailable(hashmap)
```

Add `HashMap::HashMap` as a dependnecy, e.g.:

```cmake
add_executable(my_app main.c)
target_link_libraries(my_app PRIVATE HashMap::HashMap)
```

## Contibutions and Questions

I welcome all questions and contributions. Feel free to e-mail me, or put up a pull request. The core algorithm is stable, but I'm happy to consider CMake improvements, compiler compatibility fixes, or API additions.
