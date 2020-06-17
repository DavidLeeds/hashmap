# hashmap v2
Templated type-safe hashmap implementation in C using open addressing and linear probing for collision resolution.

### Summary
This project came into existence because there are a notable lack of flexible and easy to use data structures available in C. C data structures with efficient, type-safe interfaces are virtually non-existent.  Sure, higher level languages have built-in libraries and templated classes, but plenty of embedded projects or higher level libraries are implemented in C.  It was undesirable to add a bulky library like Glib as a dependency to my projects, or grapple with a restrictive license agreement.  Searching for "C hashmap" yielded results with questionable algorithms and code quality, projects with difficult or inflexible interfaces, or projects with less desirable licenses.  I decided it was time to create my own.


### Goals
* **To scale gracefully to the full capacity of the numeric primitives in use.**  E.g. on a 32-bit machine, you should be able to load a billion+ entries without hitting any bugs relating to integer overflows.  Lookups on a hashtable with a billion entries should be performed in close to constant time, no different than lookups in a hashtable with 20 entries.  Automatic rehashing occurs and maintains a load factor of 0.75 or less.
* **To provide a clean and easy-to-use interface.**  C data structures often struggle to strike a balance between flexibility and ease of use.  To this end, I wrapped a generic C backend implementation with light-weight pre-processor macros to create a templated type-safe interface. All required type information is encoded in the hashmap declaration using the`HASHMAP()` macro. Unlike with header-only macro libraries, there is no code duplication or performance disadvantage over a traditional library with a non-type-safe `void *` interface.
* **To enable easy iteration and safe entry removal during iteration.**  Applications often need these features, and the data structure should not hold them back.  Easy to use `hashmap_foreach()` macros and a more flexible iterator interface are provided.  This hashmap also uses an open addressing scheme, which has superior iteration performance to a similar hashmap implemented using separate chaining (buckets with linked lists).  This is because fewer instructions are needed per iteration, and array traversal has superior cache performance than linked list traversal.
* **To use a very unrestrictive software license.**  Using no license was an option, but I wanted to allow the code to be tracked, simply for my own edification.  I chose the MIT license because it is the most common open source license in use, and it grants full rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell the code.  Basically, take this code and do what you want with it.  Just be nice and leave the license comment and my name at top of the file.  Feel free to add your name if you are modifying and redistributing.

### Code Example
```C
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

    if (++count > 100) {
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
```
