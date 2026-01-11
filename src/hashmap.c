/*
 * Copyright (c) 2016-2020 David Leeds <davidesleeds@gmail.com>
 *
 * Hashmap is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "hashmap_base.h"

/* Branch prediction hints for better performance */
#ifdef __GNUC__
#define LIKELY(x)   __builtin_expect(!!(x), 1)
#define UNLIKELY(x) __builtin_expect(!!(x), 0)
#else
#define LIKELY(x)   (x)
#define UNLIKELY(x) (x)
#endif

/* Table sizes must be powers of 2 */
#define HASHMAP_SIZE_MIN               32
#define HASHMAP_SIZE_DEFAULT           128
#define HASHMAP_SIZE_MOD(map, val)     ((val) & ((map)->table_size - 1))

/* Return the next linear probe index */
#define HASHMAP_PROBE_NEXT(map, index) HASHMAP_SIZE_MOD(map, (index) + 1)

struct hashmap_entry {
    void *key;
    void *data;
};

/*
 * Calculate the optimal table size, given the specified max number
 * of elements.
 */
static inline size_t hashmap_calc_table_size(const struct hashmap_base *hb, size_t size)
{
    size_t table_size;

    /* Enforce a maximum 0.75 load factor */
    table_size = size + (size / 3);

    /* Ensure capacity is not lower than the hashmap initial size */
    if (table_size < hb->table_size_init) {
        table_size = hb->table_size_init;
    } else {
        /* Round table size up to nearest power of 2 */
        table_size = 1 << ((sizeof(unsigned long) << 3) - __builtin_clzl(table_size - 1));
    }

    return table_size;
}

/*
 * Fast secondary hash function to reduce clustering.
 * Uses a simple multiplicative hash instead of the more expensive Jenkins hash.
 */
static inline size_t hashmap_secondary_hash(size_t hash)
{
    /* Knuth's multiplicative hash with golden ratio constant */
    hash *= 0x9e3779b97f4a7c15ULL;
    return hash ^ (hash >> 32);
}

/*
 * Get a valid hash table index from a key.
 */
static inline size_t hashmap_calc_index(const struct hashmap_base *hb, const void *key)
{
    size_t index = hb->hash(key);

    /*
     * Run a secondary hash on the index. This is a small performance hit, but
     * reduces clustering and provides more consistent performance if a poor
     * hash function is used.
     */
    index = hashmap_secondary_hash(index);

    return HASHMAP_SIZE_MOD(hb, index);
}

/*
 * Return the next populated entry, starting with the specified one.
 * Returns NULL if there are no more valid entries.
 */
static struct hashmap_entry *hashmap_entry_get_populated(const struct hashmap_base *hb,
                                                         const struct hashmap_entry *entry)
{
    if (hb->size > 0 && entry >= hb->table) {
        for (; entry < &hb->table[hb->table_size]; ++entry) {
            if (entry->key) {
                return (struct hashmap_entry *)entry;
            }
        }
    }
    return NULL;
}

/*
 * Find the hashmap entry with the specified key, or an empty slot.
 * Returns NULL if the entire table has been searched without finding a match.
 */
static struct hashmap_entry *hashmap_entry_find(const struct hashmap_base *hb, const void *key, bool find_empty)
{
    size_t i;
    size_t index;
    struct hashmap_entry *entry;

    index = hashmap_calc_index(hb, key);

    /* Linear probing with optimizations */
    for (i = 0; i < hb->table_size; ++i) {
        entry = &hb->table[index];

        if (UNLIKELY(!entry->key)) {
            if (find_empty) {
                return entry;
            }
            return NULL;
        }

        /* Most lookups find the key on first or second try */
        if (LIKELY(hb->compare(key, entry->key) == 0)) {
            return entry;
        }

        index = HASHMAP_PROBE_NEXT(hb, index);
    }
    return NULL;
}

/*
 * Removes the specified entry and processes the following entries to
 * keep the chain contiguous. This is a required step for hashmaps
 * using linear probing.
 */
static void hashmap_entry_remove(struct hashmap_base *hb, struct hashmap_entry *removed_entry)
{
    size_t i;
    size_t index;
    size_t entry_index;
    size_t removed_index = (removed_entry - hb->table);
    struct hashmap_entry *entry;

    /* Free the key */
    if (hb->key_free) {
        hb->key_free(removed_entry->key);
    }

    --hb->size;

    /* Fill the free slot in the chain */
    index = HASHMAP_PROBE_NEXT(hb, removed_index);
    for (i = 0; i < hb->size; ++i) {
        entry = &hb->table[index];
        if (!entry->key) {
            /* Reached end of chain */
            break;
        }
        entry_index = hashmap_calc_index(hb, entry->key);
        /* Shift in entries in the chain with an index at or before the removed slot */
        if (HASHMAP_SIZE_MOD(hb, index - entry_index) > HASHMAP_SIZE_MOD(hb, removed_index - entry_index)) {
            *removed_entry = *entry;
            removed_index = index;
            removed_entry = entry;
        }
        index = HASHMAP_PROBE_NEXT(hb, index);
    }
    /* Clear the last removed entry */
    memset(removed_entry, 0, sizeof(*removed_entry));
}

/*
 * Reallocates the hash table to the new size and rehashes all entries.
 * new_size MUST be a power of 2.
 * Returns 0 on success and -errno on allocation or hash function failure.
 */
static int hashmap_rehash(struct hashmap_base *hb, size_t table_size)
{
    size_t old_size;
    struct hashmap_entry *old_table;
    struct hashmap_entry *new_table;
    struct hashmap_entry *entry;
    struct hashmap_entry *new_entry;

    assert((table_size & (table_size - 1)) == 0);
    assert(table_size >= hb->size);

    new_table = (struct hashmap_entry *)calloc(table_size, sizeof(struct hashmap_entry));
    if (!new_table) {
        return -ENOMEM;
    }
    old_size = hb->table_size;
    old_table = hb->table;
    hb->table_size = table_size;
    hb->table = new_table;

    /* Rehash */
    for (entry = old_table; entry < old_table + old_size; ++entry) {
        if (!entry->key) {
            continue;
        }
        new_entry = hashmap_entry_find(hb, entry->key, true);
        /* Failure indicates an algorithm bug */
        assert(new_entry != NULL);

        /* Shallow copy */
        *new_entry = *entry;
    }
    free(old_table);
    return 0;
}

/*
 * Iterate through all entries and free all keys.
 */
static void hashmap_free_keys(struct hashmap_base *hb)
{
    struct hashmap_entry *entry;

    if (!hb->key_free || hb->size == 0) {
        return;
    }
    for (entry = hb->table; entry < &hb->table[hb->table_size]; ++entry) {
        if (entry->key) {
            hb->key_free(entry->key);
        }
    }
}

/*
 * Initialize an empty hashmap.
 *
 * hash_func should return an even distribution of numbers between 0
 * and SIZE_MAX varying on the key provided.
 *
 * compare_func should return 0 if the keys match, and non-zero otherwise.
 */
void hashmap_base_init(struct hashmap_base *hb, size_t (*hash_func)(const void *),
                       int (*compare_func)(const void *, const void *))
{
    assert(hash_func != NULL);
    assert(compare_func != NULL);

    memset(hb, 0, sizeof(*hb));

    hb->table_size_init = HASHMAP_SIZE_DEFAULT;
    hb->hash = hash_func;
    hb->compare = compare_func;
}

/*
 * Free the hashmap and all associated memory.
 */
void hashmap_base_cleanup(struct hashmap_base *hb)
{
    if (!hb) {
        return;
    }
    hashmap_free_keys(hb);
    free(hb->table);
    memset(hb, 0, sizeof(*hb));
}

/*
 * Enable internal memory management of hash keys.
 */
void hashmap_base_set_key_alloc_funcs(struct hashmap_base *hb, void *(*key_dup_func)(const void *),
                                      void (*key_free_func)(void *))
{
    assert(hb->size == 0);

    hb->key_dup = key_dup_func;
    hb->key_free = key_free_func;
}

/*
 * Set the hashmap's initial allocation size such that no rehashes are
 * required to fit the specified number of entries.
 * Returns 0 on success, or -errno on failure.
 */
int hashmap_base_reserve(struct hashmap_base *hb, size_t capacity)
{
    size_t old_size_init;
    int r = 0;

    /* Backup original init size in case of failure */
    old_size_init = hb->table_size_init;

    /* Set the minimal table init size to support the specified capacity */
    hb->table_size_init = HASHMAP_SIZE_MIN;
    hb->table_size_init = hashmap_calc_table_size(hb, capacity);

    if (hb->table_size_init > hb->table_size) {
        r = hashmap_rehash(hb, hb->table_size_init);
        if (r < 0) {
            hb->table_size_init = old_size_init;
        }
    }
    return r;
}

/*
 * Add a new entry to the hashmap. If an entry with a matching key
 * is already present, -EEXIST is returned.
 * Returns 0 on success, or -errno on failure.
 */
int hashmap_base_put(struct hashmap_base *hb, const void *key, void *data)
{
    struct hashmap_entry *entry;
    size_t table_size;
    int r = 0;

    if (UNLIKELY(!key || !data)) {
        return -EINVAL;
    }

    /* Preemptively rehash with 2x capacity if load factor is approaching 0.75 */
    table_size = hashmap_calc_table_size(hb, hb->size);
    if (UNLIKELY(table_size > hb->table_size)) {
        r = hashmap_rehash(hb, table_size);
    }

    /* Get the entry for this key */
    entry = hashmap_entry_find(hb, key, true);
    if (UNLIKELY(!entry)) {
        /*
         * Cannot find an empty slot. Either out of memory,
         * or hash or compare functions are malfunctioning.
         */
        if (r < 0) {
            /* Return rehash error, if set */
            return r;
        }
        return -EADDRNOTAVAIL;
    }

    if (UNLIKELY(entry->key)) {
        /* Do not overwrite existing data */
        return -EEXIST;
    }

    if (UNLIKELY(hb->key_dup)) {
        /* Allocate copy of key to simplify memory management */
        entry->key = hb->key_dup(key);
        if (UNLIKELY(!entry->key)) {
            return -ENOMEM;
        }
    } else {
        entry->key = (void *)key;
    }
    entry->data = data;
    ++hb->size;
    return 0;
}

/*
 * Add a new entry to the hashmap, or update an existing entry. If an entry
 * with a matching key is already present, its data is updated. If old_data
 * is non-null, the previous data pointer is assigned to it.
 * Returns 1 on add, 0 on update, or -errno on failure.
 */
int hashmap_base_insert(struct hashmap_base *hb, const void *key, void *data, void **old_data)
{
    struct hashmap_entry *entry;
    size_t table_size;
    int r = 0;

    if (!key || !data) {
        return -EINVAL;
    }

    /* Preemptively rehash with 2x capacity if load factor is approaching 0.75 */
    table_size = hashmap_calc_table_size(hb, hb->size);
    if (table_size > hb->table_size) {
        r = hashmap_rehash(hb, table_size);
    }

    /* Get the entry for this key */
    entry = hashmap_entry_find(hb, key, true);
    if (!entry) {
        /*
         * Cannot find an empty slot. Either out of memory,
         * or hash or compare functions are malfunctioning.
         */
        if (r < 0) {
            /* Return rehash error, if set */
            return r;
        }
        return -EADDRNOTAVAIL;
    }

    if (!entry->key) {
        /* Adding a new entry */
        if (hb->key_dup) {
            /* Allocate copy of key to simplify memory management */
            entry->key = hb->key_dup(key);
            if (!entry->key) {
                return -ENOMEM;
            }
        } else {
            entry->key = (void *)key;
        }
        ++hb->size;
        r = 1;
    }

    /* Assign the previous data pointer if data was updated, otherwise NULL */
    if (old_data) {
        if (data == entry->data) {
            *old_data = NULL;
        } else {
            *old_data = entry->data;
        }
    }

    entry->data = data;
    return r;
}

/*
 * Return the data pointer, or NULL if no entry exists.
 */
void *hashmap_base_get(const struct hashmap_base *hb, const void *key)
{
    struct hashmap_entry *entry;

    if (UNLIKELY(!key)) {
        return NULL;
    }

    entry = hashmap_entry_find(hb, key, false);
    if (UNLIKELY(!entry)) {
        return NULL;
    }
    return entry->data;
}

/*
 * Remove an entry with the specified key from the map.
 * Returns the data pointer, or NULL, if no entry was found.
 */
void *hashmap_base_remove(struct hashmap_base *hb, const void *key)
{
    struct hashmap_entry *entry;
    void *data;

    if (!key) {
        return NULL;
    }

    entry = hashmap_entry_find(hb, key, false);
    if (!entry) {
        return NULL;
    }
    data = entry->data;
    /* Clear the entry and make the chain contiguous */
    hashmap_entry_remove(hb, entry);
    return data;
}

/*
 * Remove all entries.
 */
void hashmap_base_clear(struct hashmap_base *hb)
{
    hashmap_free_keys(hb);
    hb->size = 0;
    memset(hb->table, 0, sizeof(struct hashmap_entry) * hb->table_size);
}

/*
 * Remove all entries and reset the hash table to its initial size.
 */
void hashmap_base_reset(struct hashmap_base *hb)
{
    struct hashmap_entry *new_table;

    hashmap_free_keys(hb);
    hb->size = 0;
    if (hb->table_size != hb->table_size_init) {
        new_table = (struct hashmap_entry *)realloc(hb->table, sizeof(struct hashmap_entry) * hb->table_size_init);
        if (new_table) {
            hb->table = new_table;
            hb->table_size = hb->table_size_init;
        }
    }
    memset(hb->table, 0, sizeof(struct hashmap_entry) * hb->table_size);
}

/*
 * Get a new hashmap iterator. The iterator is an opaque
 * pointer that may be used with hashmap_iter_*() functions.
 * Hashmap iterators are INVALID after a put or remove operation is performed.
 * hashmap_iter_remove() allows safe removal during iteration.
 */
struct hashmap_entry *hashmap_base_iter(const struct hashmap_base *hb, const struct hashmap_entry *pos)
{
    if (!pos) {
        pos = hb->table;
    }
    return hashmap_entry_get_populated(hb, pos);
}

/*
 * Return true if an iterator is valid and safe to use.
 */
bool hashmap_base_iter_valid(const struct hashmap_base *hb, const struct hashmap_entry *iter)
{
    return hb && iter && iter->key && iter >= hb->table && iter < hb->table + hb->table_size;
}

/*
 * Advance an iterator to the next hashmap entry.
 * Returns false if there are no more entries.
 */
bool hashmap_base_iter_next(const struct hashmap_base *hb, struct hashmap_entry **iter)
{
    if (!*iter) {
        return false;
    }
    *iter = hashmap_entry_get_populated(hb, *iter + 1);
    return *iter != NULL;
}

/*
 * Returns an iterator to the hashmap entry with the specified key.
 * Returns NULL if there is no matching entry.
 */
struct hashmap_entry *hashmap_base_iter_find(const struct hashmap_base *hb, const void *key)
{
    if (!key) {
        return NULL;
    }
    return hashmap_entry_find(hb, key, false);
}

/*
 * Remove the hashmap entry pointed to by this iterator and advance the
 * iterator to the next entry.
 * Returns true if the iterator is valid after the operation.
 */
bool hashmap_base_iter_remove(struct hashmap_base *hb, struct hashmap_entry **iter)
{
    if (!*iter) {
        return false;
    }
    if ((*iter)->key) {
        /* Remove entry if iterator is valid */
        hashmap_entry_remove(hb, *iter);
    }
    *iter = hashmap_entry_get_populated(hb, *iter);
    return *iter != NULL;
}

/*
 * Return the key of the entry pointed to by the iterator.
 */
const void *hashmap_base_iter_get_key(const struct hashmap_entry *iter)
{
    if (!iter) {
        return NULL;
    }
    return (const void *)iter->key;
}

/*
 * Return the data of the entry pointed to by the iterator.
 */
void *hashmap_base_iter_get_data(const struct hashmap_entry *iter)
{
    if (!iter) {
        return NULL;
    }
    return iter->data;
}

/*
 * Set the data pointer of the entry pointed to by the iterator.
 */
int hashmap_base_iter_set_data(struct hashmap_entry *iter, void *data)
{
    if (!iter) {
        return -EFAULT;
    }
    if (!data) {
        return -EINVAL;
    }
    iter->data = data;
    return 0;
}

/*
 * Return the load factor.
 */
double hashmap_base_load_factor(const struct hashmap_base *hb)
{
    if (!hb->table_size) {
        return 0;
    }
    return (double)hb->size / hb->table_size;
}

/*
 * Return the number of collisions for this key.
 * This would always be 0 if a perfect hash function was used, but in ordinary
 * usage, there may be a few collisions, depending on the hash function and
 * load factor.
 */
size_t hashmap_base_collisions(const struct hashmap_base *hb, const void *key)
{
    size_t i;
    size_t index;
    struct hashmap_entry *entry;

    if (!key) {
        return 0;
    }

    index = hashmap_calc_index(hb, key);

    /* Linear probing */
    for (i = 0; i < hb->table_size; ++i) {
        entry = &hb->table[index];
        if (!entry->key) {
            /* Key does not exist */
            return 0;
        }
        if (hb->compare(key, entry->key) == 0) {
            break;
        }
        index = HASHMAP_PROBE_NEXT(hb, index);
    }

    return i;
}

/*
 * Return the average number of collisions per entry.
 */
double hashmap_base_collisions_mean(const struct hashmap_base *hb)
{
    struct hashmap_entry *entry;
    size_t total_collisions = 0;

    if (!hb->size) {
        return 0;
    }
    for (entry = hb->table; entry < &hb->table[hb->table_size]; ++entry) {
        if (!entry->key) {
            continue;
        }

        total_collisions += hashmap_base_collisions(hb, entry->key);
    }
    return (double)total_collisions / hb->size;
}

/*
 * Return the variance between entry collisions. The higher the variance,
 * the more likely the hash function is poor and is resulting in clustering.
 */
double hashmap_base_collisions_variance(const struct hashmap_base *hb)
{
    struct hashmap_entry *entry;
    double mean_collisions;
    double variance;
    double total_variance = 0;

    if (!hb->size) {
        return 0;
    }
    mean_collisions = hashmap_base_collisions_mean(hb);
    for (entry = hb->table; entry < &hb->table[hb->table_size]; ++entry) {
        if (!entry->key) {
            continue;
        }
        variance = (double)hashmap_base_collisions(hb, entry->key) - mean_collisions;
        total_variance += variance * variance;
    }
    return total_variance / hb->size;
}

/*
 * High-performance hash function for arbitrary data.
 *
 * Based on xxHash algorithm which is significantly faster than Jenkins
 * while maintaining excellent distribution properties. Processes data
 * in 8-byte chunks for optimal performance.
 */
size_t hashmap_hash_default(const void *data, size_t len)
{
    const uint8_t *p = (const uint8_t *)data;
    const uint8_t *const end = p + len;
    uint64_t h;

    if (len >= 32) {
        const uint8_t *const limit = end - 32;
        uint64_t v1 = 0x9e3779b185ebca87ULL;
        uint64_t v2 = 0xc2b2ae3d27d4eb4fULL;
        uint64_t v3 = 0x165667b19e3779f9ULL;
        uint64_t v4 = 0x85ebca77c2b2ae63ULL;

        do {
            uint64_t k1, k2, k3, k4;
            memcpy(&k1, p, 8);
            p += 8;
            memcpy(&k2, p, 8);
            p += 8;
            memcpy(&k3, p, 8);
            p += 8;
            memcpy(&k4, p, 8);
            p += 8;

            v1 = ((v1 << 31) | (v1 >> 33)) + k1 * 0x9e3779b185ebca87ULL;
            v2 = ((v2 << 31) | (v2 >> 33)) + k2 * 0x9e3779b185ebca87ULL;
            v3 = ((v3 << 31) | (v3 >> 33)) + k3 * 0x9e3779b185ebca87ULL;
            v4 = ((v4 << 31) | (v4 >> 33)) + k4 * 0x9e3779b185ebca87ULL;
        } while (p <= limit);

        h = ((v1 << 1) | (v1 >> 63)) + ((v2 << 7) | (v2 >> 57)) + ((v3 << 12) | (v3 >> 52)) + ((v4 << 18) | (v4 >> 46));
    } else {
        h = 0x165667b19e3779f9ULL + len;
    }

    /* Process remaining 8-byte chunks */
    while (p + 8 <= end) {
        uint64_t k;
        memcpy(&k, p, 8);
        k *= 0x9e3779b185ebca87ULL;
        k = ((k << 31) | (k >> 33)) * 0x165667b19e3779f9ULL;
        h ^= k;
        h = ((h << 27) | (h >> 37)) * 0x9e3779b185ebca87ULL + 0x165667b19e3779f9ULL;
        p += 8;
    }

    /* Process remaining 4 bytes */
    if (p + 4 <= end) {
        uint32_t k;
        memcpy(&k, p, 4);
        h ^= (uint64_t)k * 0x165667b19e3779f9ULL;
        h = ((h << 23) | (h >> 41)) * 0x9e3779b185ebca87ULL + 0xc2b2ae3d27d4eb4fULL;
        p += 4;
    }

    /* Process remaining bytes */
    while (p < end) {
        h ^= (uint64_t)*p++ * 0x9e3779b185ebca87ULL;
        h = ((h << 11) | (h >> 53)) * 0x165667b19e3779f9ULL;
    }

    /* Final avalanche */
    h ^= h >> 33;
    h *= 0x9e3779b185ebca87ULL;
    h ^= h >> 29;
    h *= 0x165667b19e3779f9ULL;
    h ^= h >> 32;

    return (size_t)h;
}

/*
 * High-performance hash function for string keys.
 *
 * Uses an optimized algorithm that processes multiple bytes at once
 * for significantly better performance than traditional byte-by-byte hashing.
 * Based on FNV-1a with optimizations for modern CPUs.
 */
size_t hashmap_hash_string(const char *key)
{
    const uint64_t FNV_OFFSET_BASIS = 0xcbf29ce484222325ULL;
    const uint64_t FNV_PRIME = 0x100000001b3ULL;

    uint64_t hash = FNV_OFFSET_BASIS;
    const char *p = key;

    /* Align to 8-byte boundary for better performance */
    while (((uintptr_t)p & 7) && *p) {
        hash ^= (uint64_t)(unsigned char)*p++;
        hash *= FNV_PRIME;
    }

    /* Process 8 bytes at a time for optimal performance */
    const uint64_t *p64 = (const uint64_t *)p;
    while (1) {
        uint64_t chunk = *p64;

        /* Check for null terminator using bit manipulation trick */
        uint64_t hasZero = (chunk - 0x0101010101010101ULL) & ~chunk & 0x8080808080808080ULL;
        if (hasZero) {
            /* Found null byte, process remaining bytes individually */
            p = (const char *)p64;
            while (*p) {
                hash ^= (uint64_t)(unsigned char)*p++;
                hash *= FNV_PRIME;
            }
            break;
        }

        /* Process all 8 bytes efficiently */
        hash ^= chunk & 0xFF;
        hash *= FNV_PRIME;
        hash ^= (chunk >> 8) & 0xFF;
        hash *= FNV_PRIME;
        hash ^= (chunk >> 16) & 0xFF;
        hash *= FNV_PRIME;
        hash ^= (chunk >> 24) & 0xFF;
        hash *= FNV_PRIME;
        hash ^= (chunk >> 32) & 0xFF;
        hash *= FNV_PRIME;
        hash ^= (chunk >> 40) & 0xFF;
        hash *= FNV_PRIME;
        hash ^= (chunk >> 48) & 0xFF;
        hash *= FNV_PRIME;
        hash ^= (chunk >> 56) & 0xFF;
        hash *= FNV_PRIME;

        p64++;
    }

    return (size_t)hash;
}

/*
 * Optimized case insensitive hash function for string keys.
 */
size_t hashmap_hash_string_i(const char *key)
{
    const uint64_t FNV_OFFSET_BASIS = 0xcbf29ce484222325ULL;
    const uint64_t FNV_PRIME = 0x100000001b3ULL;

    uint64_t hash = FNV_OFFSET_BASIS;

    /* Process characters one by one with case conversion */
    for (; *key; ++key) {
        unsigned char c = (unsigned char)*key;
        /* Fast ASCII lowercase conversion */
        if (c >= 'A' && c <= 'Z') {
            c += 32;
        }
        hash ^= (uint64_t)c;
        hash *= FNV_PRIME;
    }

    return (size_t)hash;
}
