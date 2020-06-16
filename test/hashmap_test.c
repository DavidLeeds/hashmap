/*
 * Copyright (c) 2016-2020 David Leeds <davidesleeds@gmail.com>
 *
 * Hashmap is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>
#include <assert.h>
#include <errno.h>

#include <hashmap.h>

#define ARRAY_SIZE(array)       (sizeof(array) / sizeof(array[0]))

#define TEST_NUM_KEYS           196607    /* Results in max load factor */
#define TEST_KEY_STR_LEN        32

void **keys_str_random;
void **keys_str_sequential;
void **keys_int_random;
void **keys_int_sequential;

HASHMAP(char, void) str_map;
HASHMAP(uint64_t, uint64_t) int_map;
typedef HASHMAP(void, void) hashmap_void_t;

struct test {
    const char *name;
    const char *description;
    bool (*run)(hashmap_void_t *map, void **keys);
    bool pre_load;
};



uint64_t time_mono_us(void)
{
    struct timespec now;

    if (clock_gettime(CLOCK_MONOTONIC, &now)) {
        assert(0);
    }
    return ((uint64_t)now.tv_sec) * 1000000 + (uint64_t)(now.tv_nsec / 1000);
}

void **test_keys_alloc(size_t num)
{
    void **keys;

    keys = (void **)calloc(num, sizeof(void *));
    if (!keys) {
        printf("malloc failed\n");
        exit(1);
    }
    return keys;
}

void *test_key_alloc_random_str(void)
{
    size_t i;
    unsigned num;
    char *key;

    key = (char *)malloc(TEST_KEY_STR_LEN + 1);
    if (!key) {
        printf("malloc failed\n");
        exit(1);
    }
    for (i = 0; i < TEST_KEY_STR_LEN; ++i) {
        num = random();
        num = (num % 96) + 32;    /* ASCII printable only */
        key[i] = (char)num;
    }
    key[TEST_KEY_STR_LEN] = '\0';
    return key;
}
void *test_key_alloc_random_int(void)
{
    uint64_t *key;

    key = (uint64_t *)malloc(sizeof(*key));
    if (!key) {
        printf("malloc failed\n");
        exit(1);
    }
    /* RAND_MAX is not guaranteed to be more than 32K */
    *key = ((uint64_t)(random() & 0xffff) << 48) |
           ((uint64_t)(random() & 0xffff) << 32) |
           ((uint64_t)(random() & 0xffff) << 16) |
            (uint64_t)(random() & 0xffff);
    return key;
}

void *test_key_alloc_sequential_str(size_t index)
{
    char *key;

    key = (char *)malloc(TEST_KEY_STR_LEN + 1);
    if (!key) {
        printf("malloc failed\n");
        exit(1);
    }
    snprintf(key, TEST_KEY_STR_LEN + 1, "sequential key! %010zu", index);
    return key;
}

void *test_key_alloc_sequential_int(size_t index)
{
    uint64_t *key;

    key = (uint64_t *)malloc(sizeof(*key));
    if (!key) {
        printf("malloc failed\n");
        exit(1);
    }
    *key = index;
    return key;
}

void test_keys_generate(void)
{
    size_t i;

    srandom(99);    /* Use reproducible random sequences */

    keys_str_random =  test_keys_alloc(TEST_NUM_KEYS + 1);
    keys_str_sequential =  test_keys_alloc(TEST_NUM_KEYS + 1);
    keys_int_random =  test_keys_alloc(TEST_NUM_KEYS + 1);
    keys_int_sequential =  test_keys_alloc(TEST_NUM_KEYS + 1);
    for (i = 0; i < TEST_NUM_KEYS; ++i) {
        keys_str_random[i] = test_key_alloc_random_str();
        keys_str_sequential[i] = test_key_alloc_sequential_str(i);
        keys_int_random[i] = test_key_alloc_random_int();
        keys_int_sequential[i] = test_key_alloc_sequential_int(i);
    }
    keys_str_random[i] = NULL;
    keys_str_sequential[i] = NULL;
    keys_int_random[i] = NULL;
    keys_int_sequential[i] = NULL;
}

void test_load_keys(hashmap_void_t *map, void **keys)
{
    void **key;
    int r;

    for (key = keys; *key; ++key) {
        r = hashmap_put(map, *key, *key);
        if (r < 0) {
            printf("hashmap_put() failed: %s\n", strerror(-r));
            exit(1);
        }
    }
}

void test_reset_map(hashmap_void_t *map)
{
    hashmap_reset(map);
}

void test_print_stats(hashmap_void_t *map, const char *label)
{
    printf("Hashmap stats: %s\n", label);
    printf("    # entries:           %zu\n", hashmap_size(map));
    printf("    Table size:          %zu\n", map->map_base.table_size);
    printf("    Load factor:         %.4f\n", hashmap_load_factor(map));
    printf("    Collisions mean:     %.4f\n", hashmap_collisions_mean(map));
    printf("    Collisions variance: %.4f\n", hashmap_collisions_variance(map));

}

bool test_run(hashmap_void_t *map, void **keys, const struct test *t)
{
    bool success;
    uint64_t time_us;

    assert(t != NULL);
    assert(t->name != NULL);
    assert(t->run != NULL);

    if (t->pre_load) {
        printf("Pre-loading keys...");
        test_load_keys(map, keys);
        printf("done\n");
    }
    printf("Running...\n");
    time_us = time_mono_us();
    success = t->run(map, keys);
    time_us = time_mono_us() - time_us;
    if (success) {
        printf("Completed successfully\n");
    } else {
        printf("FAILED\n");
    }
    printf("Run time: %llu microseconds\n", (long long unsigned)time_us);
    test_print_stats(map, t->name);
    test_reset_map(map);
    return success;
}

bool test_run_all(hashmap_void_t *map, void **keys,
        const struct test *tests, size_t num_tests, const char *env)
{
    const struct test *t;
    size_t num_failed = 0;

    printf("\n**************************************************\n");
    printf("Starting test series:\n");
    printf("    %s\n", env);
    printf("**************************************************\n\n");
    for (t = tests; t < &tests[num_tests]; ++t) {
        printf("\n**************************************************\n");
        printf("Test %02u: %s\n", (unsigned)(t - tests) + 1, t->name);
        if (t->description) {
            printf("    Description: %s\n", t->description);
        }
        printf("\n");
        if (!test_run(map, keys, t)) {
            ++num_failed;
        }
    }
    printf("\n**************************************************\n");
    printf("Test results:\n");
    printf("    Passed: %zu\n", num_tests - num_failed);
    printf("    Failed: %zu\n", num_failed);
    printf("**************************************************\n");
    return (num_failed == 0);
}

/*
 * Worst case hash function.
 */
size_t test_hash_uint64_bad1(const uint64_t *key)
{
    return 999;
}

/*
 * Potentially bad hash function. Depending on the linear probing
 * implementation, this could cause clustering and long chains when
 * consecutive numeric keys are loaded.
 */
size_t test_hash_uint64_bad2(const uint64_t *key)
{
    return *key;
}

/*
 * Potentially bad hash function. Depending on the linear probing
 * implementation, this could cause clustering and long chains when
 * consecutive numeric keys are loaded.
 */
size_t test_hash_uint64_bad3(const uint64_t *key)
{
    return *key + *key;
}

/*
 * Use generic hash algorithm supplied by the hashmap library.
 */
size_t test_hash_uint64(const uint64_t *key)
{
    return hashmap_hash_default(key, sizeof(*key));
}

int test_compare_uint64(const uint64_t *a, const uint64_t *b)
{
    return memcmp(a, b, sizeof(uint64_t));
}

bool test_put(hashmap_void_t *map, void **keys)
{
    void **key;
    int r;

    for (key = keys; *key; ++key) {
        r = hashmap_put(map, *key, *key);
        if (r < 0) {
            printf("hashmap_put failed: %s\n", strerror(-r));
            return false;
        }
    }
    return true;
}

bool test_put_existing(hashmap_void_t *map, void **keys)
{
    void **key;
    int r;
    int temp_data = 99;

    for (key = keys; *key; ++key) {
        r = hashmap_put(map, *key, &temp_data);
        if (r != -EEXIST) {
            printf("did not return existing data: %s\n", strerror(-r));
            return false;
        }
    }
    return true;
}

bool test_get(hashmap_void_t *map, void **keys)
{
    void **key;
    void *data;

    for (key = keys; *key; ++key) {
        data = hashmap_get(map, *key);
        if (!data) {
            printf("entry not found\n");
            return false;
        }
        if (data != *key) {
            printf("got wrong entry\n");
            return false;
        }
    }
    return true;
}

bool test_get_nonexisting(hashmap_void_t *map, void **keys)
{
    void **key;
    void *data;
    const char *fake_key = "test_get_nonexisting fake key!";

    for (key = keys; *key; ++key) {
        data = hashmap_get(map, fake_key);
        if (data) {
            printf("unexpected entry found\n");
            return false;
        }
    }
    return true;
}

bool test_remove(hashmap_void_t *map, void **keys)
{
    void **key;
    void *data;

    for (key = keys; *key; ++key) {
        data = hashmap_remove(map, *key);
        if (!data) {
            printf("entry not found\n");
            return false;
        }
        if (data != *key) {
            printf("removed wrong entry\n");
            return false;
        }
    }
    return true;
}

bool test_put_remove(hashmap_void_t *map, void **keys)
{
    size_t i = 0;
    void **key;
    void *data;
    int r;

    if (!test_put(map, keys)) {
        return false;
    }
    for (key = keys; *key; ++key) {
        if (i++ >= TEST_NUM_KEYS / 2) {
            break;
        }
        data = hashmap_remove(map, *key);
        if (!data) {
            printf("key not found\n");
            return false;
        }
        if (data != *key) {
            printf("removed wrong entry\n");
            return false;
        }
    }
    test_print_stats(map, "test_put_remove done");
    i = 0;
    for (key = keys; *key; ++key) {
        if (i++ >= TEST_NUM_KEYS / 2) {
            break;
        }
        r = hashmap_put(map, *key, *key);
        if (r < 0) {
            printf("hashmap_put failed: %s\n", strerror(-r));
            return false;
        }
    }
    return true;
}

bool test_iterate(hashmap_void_t *map, void **keys)
{
    size_t i = 0;
    const void *key;
    void *data;

    hashmap_foreach(key, data, map) {
        ++i;
        if (!key) {
            printf("key %zu is NULL\n", i);
            return false;
        }
        if (!data) {
            printf("data %zu is NULL\n", i);
            return false;
        }
    }
    if (i != TEST_NUM_KEYS) {
        printf("did not iterate through all entries: "
                "observed %zu, expected %u\n", i, TEST_NUM_KEYS);
        return false;
    }
    return true;
}

bool test_iterate_remove(hashmap_void_t *map, void **keys)
{
    size_t i = 0;
    const void *key;
    void *data, *temp;

    hashmap_foreach_safe(key, data, map, temp) {
        ++i;
        if (hashmap_get(map, key) != data) {
            printf("invalid iterator on entry #%zu\n", i);
            return false;
        }
        if (hashmap_remove(map, key) != data) {
            printf("key/data mismatch %zu: %p != %p\n", i, key, data);
        }
    }
    if (i != TEST_NUM_KEYS) {
        printf("did not iterate through all entries: "
                "observed %zu, expected %u\n", i, TEST_NUM_KEYS);
        return false;
    }
    return true;
}

bool test_iterate_remove_odd(hashmap_void_t *map, void **keys)
{
    size_t size = hashmap_size(map);
    size_t i = 0;
    size_t removed = 0;
    const void *key;
    void *temp;

    hashmap_foreach_key_safe(key, map, temp) {
        if (i & 1) {
            /* Remove odd indices */
            if (!hashmap_remove(map, key)) {
                printf("could not remove expected key\n");
                return false;
            }
            ++removed;
        }
        ++i;
    }

    if (hashmap_size(map) != size - removed) {
        printf("foreach delete did not remove expected # of entries: "
                "contains %zu vs. expected %zu\n", hashmap_size(map),
                size - removed);
        return false;
    }
    return true;
}

bool test_clear(hashmap_void_t *map, void **keys)
{
    hashmap_clear(map);
    return true;
}

bool test_reset(hashmap_void_t *map, void **keys)
{
    hashmap_reset(map);
    return true;
}

const struct test tests[] = {
        {
                .name = "put performance",
                .description = "put new hash keys",
                .run = test_put
        },
        {
                .name = "put existing performance",
                .description = "attempt to put existing hash keys",
                .run = test_put_existing,
                .pre_load = true
        },
        {
                .name = "get existing performance",
                .description = "get existing hash keys",
                .run = test_get,
                .pre_load = true
        },
        {
                .name = "get non-existing performance",
                .description = "get nonexistent hash keys",
                .run = test_get_nonexisting,
                .pre_load = true
        },
        {
                .name = "remove performance",
                .description = "remove hash keys",
                .run = test_remove,
                .pre_load = true
        },
        {
                .name = "mixed put/remove performance",
                .description = "put, remove 1/2, then put them back",
                .run = test_put_remove
        },
        {
                .name = "iterate performance",
                .description = "iterate through entries",
                .run = test_iterate,
                .pre_load = true
        },
        {
                .name = "iterate remove all",
                .description = "iterate and remove all entries",
                .run = test_iterate_remove,
                .pre_load = true
        },
        {
                .name = "iterate remove odd indices",
                .description = "iterate and delete alternate entries",
                .run = test_iterate_remove_odd,
                .pre_load = true
        },
        {
                .name = "clear performance",
                .description = "clear entries",
                .run = test_clear,
                .pre_load = true
        },
        {
                .name = "reset performance",
                .description = "reset entries",
                .run = test_reset,
                .pre_load = true
        }
};

/*
 * Main function
 */
int main(int argc, char **argv)
{
    bool success = true;

    /* Initialize */
    printf("Initializing hash maps...\n");
    hashmap_init(&str_map, hashmap_hash_string, strcmp);

//    hashmap_set_key_alloc_funcs(&str_map, strdup, (void(*)(char *))free);

    hashmap_init(&int_map, test_hash_uint64_bad2, test_compare_uint64);

    printf("Generating test %u test keys...", TEST_NUM_KEYS);
    test_keys_generate();
    printf("done\n");

    printf("Running tests\n\n");
    success &= test_run_all((hashmap_void_t *)&str_map, keys_str_random, tests,
            ARRAY_SIZE(tests), "Hashmap w/randomized string keys");
    success &= test_run_all((hashmap_void_t *)&str_map, keys_str_sequential, tests,
            ARRAY_SIZE(tests), "Hashmap w/sequential string keys");

    success &= test_run_all((hashmap_void_t *)&int_map, keys_int_random, tests,
            ARRAY_SIZE(tests), "Hashmap w/randomized integer keys");

    success &= test_run_all((hashmap_void_t *)&int_map, keys_int_sequential, tests,
            ARRAY_SIZE(tests), "Hashmap w/sequential integer keys");

    printf("\nTests finished\n");

    hashmap_cleanup(&str_map);
    hashmap_cleanup(&int_map);

    if (!success) {
        printf("Tests FAILED\n");
        exit(1);
    }
    return 0;
}
