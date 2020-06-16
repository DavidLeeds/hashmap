/*
 * Copyright (c) 2016-2020 David Leeds <davidesleeds@gmail.com>
 *
 * Hashmap is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include <hashmap.h>

/* Some sample data structure with a string key */
struct blob {
    char key[32];
    size_t data_len;
    unsigned char data[1024];
};

/*
 * Contrived function to allocate blob structures and populate
 * them with randomized data.
 *
 * Returns NULL when there are no more blobs to load.
 */
struct blob *blob_load(void)
{
    static size_t count = 0;
    struct blob *b;

    if (count++ > 100) {
        return NULL;
    }

    if ((b = malloc(sizeof(*b))) == NULL) {
        return NULL;
    }
    snprintf(b->key, sizeof(b->key), "%02lx", random() % 100);
    b->data_len = random() % 10;
    memset(b->data, random(), b->data_len);

    return b;
}

int main(int argc, char **argv)
{
    /* Declare type-specific hashmap structure */
    HASHMAP(char, struct blob) map;
    const char *key;
    struct blob *b;
    void *temp;
    int r;

    /* Initialize with default string key hash function and comparator */
    hashmap_init(&map, hashmap_hash_string, strcmp);

    /* Load some sample data into the map and discard duplicates */
    while ((b = blob_load()) != NULL) {
        r = hashmap_put(&map, b->key, b);
        if (r < 0) {
            /* Expect -EEXIST return value for duplicates */
            printf("putting blob[%s] failed: %s\n", b->key, strerror(-r));
            free(b);
        }
    }

    /* Lookup a blob with key "AbCdEf" */
    b = hashmap_get(&map, "AbCdEf");
    if (b) {
        printf("Found blob[%s]\n", b->key);
    }

    /* Iterate through all blobs and print each one */
    hashmap_foreach(key, b, &map) {
        printf("blob[%s]: data_len %zu bytes\n", key, b->data_len);
    }

    /* Remove all blobs with no data (using remove-safe foreach macro) */
    hashmap_foreach_data_safe(b, &map, temp) {
        if (b->data_len == 0) {
            printf("Discarding blob[%s] with no data\n", b->key);
            hashmap_remove(&map, b->key);
            free(b);
        }
    }

    /* Cleanup time: free all the blobs, and destruct the hashmap */
    hashmap_foreach_data(b, &map) {
        free(b);
    }
    hashmap_cleanup(&map);

    return 0;
}

