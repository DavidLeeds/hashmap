/*
 * Copyright (c) 2016-2020 David Leeds <davidesleeds@gmail.com>
 *
 * Hashmap is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>

#include "hashmap_base.h"

/*
 * INTERNAL USE ONLY: Updates an iterator structure after the current element was removed.
 */
#define __HASHMAP_ITER_RESET(iter)                                                                                     \
    ({ ((iter)->iter_pos = hashmap_base_iter((iter)->iter_map, (iter)->iter_pos)) != NULL; })

/*
 * INTERNAL USE ONLY: foreach macro internals.
 */
#define __HASHMAP_CONCAT_2(x, y)       x##y
#define __HASHMAP_CONCAT(x, y)         __HASHMAP_CONCAT_2(x, y)
#define __HASHMAP_MAKE_UNIQUE(prefix)  __HASHMAP_CONCAT(__HASHMAP_CONCAT(prefix, __COUNTER__), _)
#define __HASHMAP_UNIQUE(unique, name) __HASHMAP_CONCAT(unique, name)
#define __HASHMAP_FOREACH(x, key, data, h)                                                                             \
    for (HASHMAP_ITER(*(h)) __HASHMAP_UNIQUE(x, it) = hashmap_iter(h);                                                 \
         ((key) = hashmap_iter_get_key(&__HASHMAP_UNIQUE(x, it))) &&                                                   \
         ((data) = hashmap_iter_get_data(&__HASHMAP_UNIQUE(x, it)));                                                   \
         hashmap_iter_next(&__HASHMAP_UNIQUE(x, it)))
#define __HASHMAP_FOREACH_SAFE(x, key, data, h, pos)                                                                   \
    for (HASHMAP_ITER(*(h)) __HASHMAP_UNIQUE(x, it) = hashmap_iter(h);                                                 \
         ((pos) = (void *)((key) = hashmap_iter_get_key(&__HASHMAP_UNIQUE(x, it)))) &&                                 \
         ((data) = hashmap_iter_get_data(&__HASHMAP_UNIQUE(x, it)));                                                   \
         ((pos) == (void *)hashmap_iter_get_key(&__HASHMAP_UNIQUE(x, it))) ?                                           \
             hashmap_iter_next(&__HASHMAP_UNIQUE(x, it)) :                                                             \
             __HASHMAP_ITER_RESET(&__HASHMAP_UNIQUE(x, it)))
#define __HASHMAP_FOREACH_KEY(x, key, h)                                                                               \
    for (HASHMAP_ITER(*(h)) __HASHMAP_UNIQUE(x, it) = hashmap_iter(h);                                                 \
         (key = hashmap_iter_get_key(&__HASHMAP_UNIQUE(x, it))); hashmap_iter_next(&__HASHMAP_UNIQUE(x, it)))
#define __HASHMAP_FOREACH_KEY_SAFE(x, key, h, pos)                                                                     \
    for (HASHMAP_ITER(*(h)) __HASHMAP_UNIQUE(x, it) = hashmap_iter(h);                                                 \
         ((pos) = (void *)((key) = hashmap_iter_get_key(&__HASHMAP_UNIQUE(x, it))));                                   \
         ((pos) == (void *)hashmap_iter_get_key(&__HASHMAP_UNIQUE(x, it))) ?                                           \
             hashmap_iter_next(&__HASHMAP_UNIQUE(x, it)) :                                                             \
             __HASHMAP_ITER_RESET(&__HASHMAP_UNIQUE(x, it)))
#define __HASHMAP_FOREACH_DATA(x, data, h)                                                                             \
    for (HASHMAP_ITER(*(h)) __HASHMAP_UNIQUE(x, it) = hashmap_iter(h);                                                 \
         (data = hashmap_iter_get_data(&__HASHMAP_UNIQUE(x, it))); hashmap_iter_next(&__HASHMAP_UNIQUE(x, it)))
#define __HASHMAP_FOREACH_DATA_SAFE(x, data, h, pos)                                                                   \
    for (HASHMAP_ITER(*(h)) __HASHMAP_UNIQUE(x, it) = hashmap_iter(h);                                                 \
         ((pos) = (void *)hashmap_iter_get_key(&__HASHMAP_UNIQUE(x, it))) &&                                           \
         ((data) = hashmap_iter_get_data(&__HASHMAP_UNIQUE(x, it)));                                                   \
         ((pos) == (void *)hashmap_iter_get_key(&__HASHMAP_UNIQUE(x, it))) ?                                           \
             hashmap_iter_next(&__HASHMAP_UNIQUE(x, it)) :                                                             \
             __HASHMAP_ITER_RESET(&__HASHMAP_UNIQUE(x, it)))

/*
 * Template macro to define a type-specific hashmap.
 *
 * Example declarations:
 *   HASHMAP(int, struct foo) map1;
 *   // key_type:       const int *
 *   // data_type:      struct foo *
 *
 *   HASHMAP(char, char) map2;
 *   // key_type:       const char *
 *   // data_type:      char *
 */
#define HASHMAP(key_type, data_type)                                                                                   \
    struct {                                                                                                           \
        struct hashmap_base map_base;                                                                                  \
        struct {                                                                                                       \
            const key_type *t_key;                                                                                     \
            data_type *t_data;                                                                                         \
            size_t (*t_hash_func)(const key_type *);                                                                   \
            int (*t_compare_func)(const key_type *, const key_type *);                                                 \
            key_type *(*t_key_dup_func)(const key_type *);                                                             \
            void (*t_key_free_func)(key_type *);                                                                       \
            int (*t_foreach_func)(const key_type *, data_type *, void *);                                              \
            struct {                                                                                                   \
                struct hashmap_base *iter_map;                                                                         \
                struct hashmap_entry *iter_pos;                                                                        \
                struct {                                                                                               \
                    const key_type *t_key;                                                                             \
                    data_type *t_data;                                                                                 \
                } iter_types[0];                                                                                       \
            } t_iterator;                                                                                              \
        } map_types[0];                                                                                                \
    }

/*
 * Template macro to define a hashmap iterator.
 *
 * Example declarations:
 *   HASHMAP_ITER(my_hashmap) iter;
 */
#define HASHMAP_ITER(hashmap_type) typeof((hashmap_type).map_types->t_iterator)

/*
 * Initialize an empty hashmap.
 *
 * Parameters:
 *   HASHMAP(<key_type>, <data_type>) *h - hashmap pointer
 *   size_t (*hash_func)(const <key_type> *) - hash function that should return an
 *              even distribution of numbers between 0 and SIZE_MAX varying on the key provided.
 *   int (*compare_func)(const <key_type> *, const <key_type> *) - key comparison function that
 *              should return 0 if the keys match, and non-zero otherwise.
 *
 * This library provides some basic hash functions:
 *   size_t hashmap_hash_default(const void *data, size_t len) - Jenkins one-at-a-time hash for
 *           keys of any data type. Create a type-specific wrapper function to pass to hashmap_init().
 *   size_t hashmap_hash_string(const char *key) - case sensitive string hash function.
 *           Pass this directly to hashmap_init().
 *   size_t hashmap_hash_string_i(const char *key) - non-case sensitive string hash function.
 *           Pass this directly to hashmap_init().
 */
#define hashmap_init(h, hash_func, compare_func)                                                                       \
    do {                                                                                                               \
        typeof((h)->map_types->t_hash_func) __map_hash = (hash_func);                                                  \
        typeof((h)->map_types->t_compare_func) __map_compare = (compare_func);                                         \
        hashmap_base_init(&(h)->map_base, (size_t (*)(const void *))__map_hash,                                        \
                          (int (*)(const void *, const void *))__map_compare);                                         \
    } while (0)

/*
 * Free the hashmap and all associated memory.
 *
 * Parameters:
 *   HASHMAP(<key_type>, <data_type>) *h - hashmap pointer
 */
#define hashmap_cleanup(h) hashmap_base_cleanup(&(h)->map_base)

/*
 * Enable internal memory allocation and management for hash keys.
 *
 * Parameters:
 *   HASHMAP(<key_type>, <data_type>) *h - hashmap pointer
 *   <key_type> *(*key_dup_func)(const <key_type> *) - allocate a copy of the key to be
 *              managed internally by the hashmap.
 *   void (*key_free_func)(<key_type> *) - free resources associated with a key
 */
#define hashmap_set_key_alloc_funcs(h, key_dup_func, key_free_func)                                                    \
    do {                                                                                                               \
        typeof((h)->map_types->t_key_dup_func) __map_key_dup = (key_dup_func);                                         \
        typeof((h)->map_types->t_key_free_func) __map_key_free = (key_free_func);                                      \
        hashmap_base_set_key_alloc_funcs(&(h)->map_base, (void *(*)(const void *))__map_key_dup,                       \
                                         (void (*)(void *))__map_key_free);                                            \
    } while (0)

/*
 * Return the number of entries in the hashmap.
 *
 * Parameters:
 *   const HASHMAP(<key_type>, <data_type>) *h - hashmap pointer
 */
#define hashmap_size(h)              ((typeof((h)->map_base.size))(h)->map_base.size)

/*
 * Return true if the hashmap is empty.
 *
 * Parameters:
 *   const HASHMAP(<key_type>, <data_type>) *h - hashmap pointer
 */
#define hashmap_empty(h)             (hashmap_size(h) == 0)

/*
 * Set the hashmap's initial allocation size such that no rehashes are
 * required to fit the specified number of entries.
 *
 * Parameters:
 *   HASHMAP(<key_type>, <data_type>) *h - hashmap pointer
 *   size_t capacity - number of entries.
 *
 * Returns 0 on success, or -errno on failure.
 */
#define hashmap_reserve(h, capacity) hashmap_base_reserve(&(h)->map_base, capacity)

/*
 * Get the hashmap's present allocation size.
 *
 * Parameters:
 *   HASHMAP(<key_type>, <data_type>) *h - hashmap pointer
 *
 * Returns 0 on success, or -errno on failure.
 */
#define hashmap_capacity(h)          ((typeof((h)->map_base.table_size))(h)->map_base.table_size)

/*
 * Add a new entry to the hashmap. If an entry with a matching key is already
 * present, -EEXIST is returned.
 *
 * Parameters:
 *   HASHMAP(<key_type>, <data_type>) *h - hashmap pointer
 *   <key_type> *key - pointer to the entry's key
 *   <data_type> *data - pointer to the entry's data
 *
 * Returns 0 on success, or -errno on failure.
 */
#define hashmap_put(h, key, data)                                                                                      \
    ({                                                                                                                 \
        typeof((h)->map_types->t_key) __map_key = (key);                                                               \
        typeof((h)->map_types->t_data) __map_data = (data);                                                            \
        hashmap_base_put(&(h)->map_base, (const void *)__map_key, (void *)__map_data);                                 \
    })

/*
 * Add a new entry to the hashmap, or update an existing entry. If an entry
 * with a matching key is already present, its data is updated. If old_data
 * is non-null, the previous data pointer is assigned to it.
 *
 * Parameters:
 *   HASHMAP(<key_type>, <data_type>) *h - hashmap pointer
 *   <key_type> *key - pointer to the entry's key
 *   <data_type> *data - pointer to the entry's data
 *   <data_type> **old_data - optional pointer to assign the previous data to
 *
 * Returns 1 on add, 0 on update, or -errno on failure.
 */
#define hashmap_insert(h, key, data, old_data)                                                                         \
    ({                                                                                                                 \
        typeof((h)->map_types->t_key) __map_key = (key);                                                               \
        typeof((h)->map_types->t_data) __map_data = (data);                                                            \
        typeof((h)->map_types->t_data) *__map_old_data = (old_data);                                                   \
        hashmap_base_insert(&(h)->map_base, (const void *)__map_key, (void *)__map_data, (void **)__map_old_data);     \
    })

/*
 * Do a constant-time lookup of a hashmap entry.
 *
 * Parameters:
 *   HASHMAP(<key_type>, <data_type>) *h - hashmap pointer
 *   <key_type> *key - pointer to the key to lookup
 *
 * Return the data pointer, or NULL if no entry exists.
 */
#define hashmap_get(h, key)                                                                                            \
    ({                                                                                                                 \
        typeof((h)->map_types->t_key) __map_key = (key);                                                               \
        (typeof((h)->map_types->t_data))hashmap_base_get(&(h)->map_base, (const void *)__map_key);                     \
    })

/*
 * Return true if the hashmap contains an entry with the specified key.
 *
 * Parameters:
 *   const HASHMAP(<key_type>, <data_type>) *h - hashmap pointer
 */
#define hashmap_contains(h, key) (hashmap_get(h, key) != NULL)

/*
 * Remove an entry with the specified key from the map.
 *
 * Parameters:
 *   HASHMAP(<key_type>, <data_type>) *h - hashmap pointer
 *   <key_type> *key - pointer to the key to remove
 *
 * Returns the data pointer, or NULL, if no entry was found.
 *
 * Note: it is not safe to call this function while iterating, unless
 * the "safe" variant of the foreach macro is used, and only the current
 * key is removed.
 */
#define hashmap_remove(h, key)                                                                                         \
    ({                                                                                                                 \
        typeof((h)->map_types->t_key) __map_key = (key);                                                               \
        (typeof((h)->map_types->t_data))hashmap_base_remove(&(h)->map_base, (const void *)__map_key);                  \
    })

/*
 * Remove all entries.
 *
 * Parameters:
 *   HASHMAP(<key_type>, <data_type>) *h - hashmap pointer
 */
#define hashmap_clear(h)            hashmap_base_clear(&(h)->map_base)

/*
 * Remove all entries and reset the hash table to its initial size.
 *
 * Parameters:
 *   HASHMAP(<key_type>, <data_type>) *h - hashmap pointer
 */
#define hashmap_reset(h)            hashmap_base_reset(&(h)->map_base)

/*
 * Return an iterator for this hashmap. The iterator is a type-specific
 * structure that may be declared using the HASHMAP_ITER() macro.
 *
 * Parameters:
 *   HASHMAP(<key_type>, <data_type>) *h - hashmap pointer
 */
#define hashmap_iter(h)             ((HASHMAP_ITER(*(h))){&(h)->map_base, hashmap_base_iter(&(h)->map_base, NULL)})

/*
 * Return true if an iterator is valid and safe to use.
 *
 * Parameters:
 *   HASHMAP_ITER(<hashmap_type>) *iter - iterator pointer
 */
#define hashmap_iter_valid(iter)    hashmap_base_iter_valid((iter)->iter_map, (iter)->iter_pos)

/*
 * Advance an iterator to the next hashmap entry.
 *
 * Parameters:
 *   HASHMAP_ITER(<hashmap_type>) *iter - iterator pointer
 *
 * Returns true if the iterator is valid after the operation.
 */
#define hashmap_iter_next(iter)     hashmap_base_iter_next((iter)->iter_map, &(iter)->iter_pos)

/*
 * This function behaves like hashmap_get(), but returns an iterator.
 * This provides an efficient way to access and remove an entry without
 * performing two lookups.
 *
 * Parameters:
 *   HASHMAP(<key_type>, <data_type>) *h - hashmap pointer
 *   <key_type> *key - pointer to the key to lookup
 *
 * Returns a valid iterator if the key exists, otherwise an invalid iterator.
 */
#define hashmap_iter_find(h, key)   ((HASHMAP_ITER(*(h))){&(h)->map_base, hashmap_base_iter_find(&(h)->map_base, key)})

/*
 * Remove the hashmap entry pointed to by this iterator and advance the
 * iterator to the next entry.
 *
 * Parameters:
 *   HASHMAP_ITER(<hashmap_type>) *iter - iterator pointer
 *
 * Returns true if the iterator is valid after the operation.
 */
#define hashmap_iter_remove(iter)   hashmap_base_iter_remove((iter)->iter_map, &(iter)->iter_pos)

/*
 * Return the key of the entry pointed to by the iterator.
 *
 * Parameters:
 *   HASHMAP_ITER(<hashmap_type>) *iter - iterator pointer
 */
#define hashmap_iter_get_key(iter)  ((typeof((iter)->iter_types->t_key))hashmap_base_iter_get_key((iter)->iter_pos))

/*
 * Return the data of the entry pointed to by the iterator.
 *
 * Parameters:
 *   HASHMAP_ITER(<hashmap_type>) *iter - iterator pointer
 */
#define hashmap_iter_get_data(iter) ((typeof((iter)->iter_types->t_data))hashmap_base_iter_get_data((iter)->iter_pos))

/*
 * Set the data pointer of the entry pointed to by the iterator.
 *
 * Parameters:
 *   HASHMAP_ITER(<hashmap_type>) *iter - iterator pointer
 *   <data_type> *data - new data pointer
 */
#define hashmap_iter_set_data(iter, data)                                                                              \
    ({                                                                                                                 \
        (typeof((iter)->iter_types->t_data))__map_data = (data);                                                       \
    hashmap_base_iter_set_data((iter)->iter_pos), (void *)__map_data);                                                 \
    })

/*
 * Convenience macro to iterate through the contents of a hashmap.
 * key and data are assigned pointers to the current hashmap entry.
 * It is NOT safe to modify the hashmap while iterating.
 *
 * Parameters:
 *   const <key_type> *key - key pointer assigned on each iteration
 *   <data_type> *data - data pointer assigned on each iteration
 *   HASHMAP(<key_type>, <data_type>) *h - hashmap pointer
 */
#define hashmap_foreach(key, data, h) __HASHMAP_FOREACH(__HASHMAP_MAKE_UNIQUE(__map), (key), (data), (h))

/*
 * Convenience macro to iterate through the contents of a hashmap.
 * key and data are assigned pointers to the current hashmap entry.
 * Unlike hashmap_foreach(), it is safe to call hashmap_remove() on the
 * current entry.
 *
 * Parameters:
 *   const <key_type> *key - key pointer assigned on each iteration
 *   <data_type> *data - data pointer assigned on each iteration
 *   HASHMAP(<key_type>, <data_type>) *h - hashmap pointer
 *   void *pos - opaque pointer assigned on each iteration
 */
#define hashmap_foreach_safe(key, data, h, pos)                                                                        \
    __HASHMAP_FOREACH_SAFE(__HASHMAP_MAKE_UNIQUE(__map), (key), (data), (h), (pos))

/*
 * Convenience macro to iterate through the keys of a hashmap.
 * key is assigned a pointer to the current hashmap entry.
 * It is NOT safe to modify the hashmap while iterating.
 *
 * Parameters:
 *   const <key_type> *key - key pointer assigned on each iteration
 *   HASHMAP(<key_type>, <data_type>) *h - hashmap pointer
 */
#define hashmap_foreach_key(key, h) __HASHMAP_FOREACH_KEY(__HASHMAP_MAKE_UNIQUE(__map), (key), (h))

/*
 * Convenience macro to iterate through the keys of a hashmap.
 * key is assigned a pointer to the current hashmap entry.
 * Unlike hashmap_foreach_key(), it is safe to call hashmap_remove() on the
 * current entry.
 *
 * Parameters:
 *   const <key_type> *key - key pointer assigned on each iteration
 *   HASHMAP(<key_type>, <data_type>) *h - hashmap pointer
 *   void *pos - opaque pointer assigned on each iteration
 */
#define hashmap_foreach_key_safe(key, h, pos)                                                                          \
    __HASHMAP_FOREACH_KEY_SAFE(__HASHMAP_MAKE_UNIQUE(__map), (key), (h), (pos))

/*
 * Convenience macro to iterate through the data of a hashmap.
 * data is assigned a pointer to the current hashmap entry.
 * It is NOT safe to modify the hashmap while iterating.
 *
 * Parameters:
 *   <data_type> *data - data pointer assigned on each iteration
 *   HASHMAP(<key_type>, <data_type>) *h - hashmap pointer
 */
#define hashmap_foreach_data(data, h) __HASHMAP_FOREACH_DATA(__HASHMAP_MAKE_UNIQUE(__map), (data), (h))

/*
 * Convenience macro to iterate through the data of a hashmap.
 * data is assigned a pointer to the current hashmap entry.
 * Unlike hashmap_foreach_data(), it is safe to call hashmap_remove() on the
 * current entry.
 *
 * Parameters:
 *   <data_type> *data - data pointer assigned on each iteration
 *   HASHMAP(<key_type>, <data_type>) *h - hashmap pointer
 *   void *pos - opaque pointer assigned on each iteration
 */
#define hashmap_foreach_data_safe(data, h, pos)                                                                        \
    __HASHMAP_FOREACH_DATA_SAFE(__HASHMAP_MAKE_UNIQUE(__map), (data), (h), (pos))

/*
 * Return the load factor.
 *
 * Parameters:
 *   HASHMAP(<key_type>, <data_type>) *h - hashmap pointer
 */
#define hashmap_load_factor(h) hashmap_base_load_factor(&(h)->map_base)

/*
 * Return the number of collisions for this key.
 * This would always be 0 if a perfect hash function was used, but in ordinary
 * usage, there may be a few collisions, depending on the hash function and
 * load factor.
 *
 * Parameters:
 *   HASHMAP(<key_type>, <data_type>) *h - hashmap pointer
 *   <key_type> *key - pointer to the entry's key
 */
#define hashmap_collisions(h, key)                                                                                     \
    ({                                                                                                                 \
        typeof((h)->map_types->t_key) __map_key = (key);                                                               \
        hashmap_base_collisions(&(h)->map_base, (const void *)__map_key);                                              \
    })

/*
 * Return the average number of collisions per entry.
 *
 * Parameters:
 *   HASHMAP(<key_type>, <data_type>) *h - hashmap pointer
 */
#define hashmap_collisions_mean(h)     hashmap_base_collisions_mean(&(h)->map_base)

/*
 * Return the variance between entry collisions. The higher the variance,
 * the more likely the hash function is poor and is resulting in clustering.
 *
 * Parameters:
 *   HASHMAP(<key_type>, <data_type>) *h - hashmap pointer
 */
#define hashmap_collisions_variance(h) hashmap_base_collisions_variance(&(h)->map_base)

#ifdef __cplusplus
}
#endif
