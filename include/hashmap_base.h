/*
 * Copyright (c) 2016-2020 David Leeds <davidesleeds@gmail.com>
 *
 * Hashmap is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#pragma once

struct hashmap_entry;

struct hashmap_base {
    size_t table_size_init;
    size_t table_size;
    size_t size;
    struct hashmap_entry *table;
    size_t (*hash)(const void *);
    int (*compare)(const void *, const void *);
    void *(*key_dup)(const void *);
    void (*key_free)(void *);
};

void hashmap_base_init(struct hashmap_base *hb,
        size_t (*hash_func)(const void *), int (*compare_func)(const void *, const void *));
void hashmap_base_cleanup(struct hashmap_base *hb);

void hashmap_base_set_key_alloc_funcs(struct hashmap_base *hb,
    void *(*key_dup_func)(const void *), void (*key_free_func)(void *));

int hashmap_base_reserve(struct hashmap_base *hb, size_t capacity);

int hashmap_base_put(struct hashmap_base *hb, const void *key, void *data);
void *hashmap_base_get(const struct hashmap_base *hb, const void *key);
void *hashmap_base_remove(struct hashmap_base *hb, const void *key);

void hashmap_base_clear(struct hashmap_base *hb);
void hashmap_base_reset(struct hashmap_base *hb);

struct hashmap_entry *hashmap_base_iter(const struct hashmap_base *hb,
        const struct hashmap_entry *pos);
bool hashmap_base_iter_valid(const struct hashmap_base *hb, const struct hashmap_entry *iter);
bool hashmap_base_iter_next(const struct hashmap_base *hb, struct hashmap_entry **iter);
bool hashmap_base_iter_remove(struct hashmap_base *hb, struct hashmap_entry **iter);
const void *hashmap_base_iter_get_key(const struct hashmap_entry *iter);
void *hashmap_base_iter_get_data(const struct hashmap_entry *iter);
int hashmap_base_iter_set_data(struct hashmap_entry *iter, void *data);

double hashmap_base_load_factor(const struct hashmap_base *hb);
size_t hashmap_base_collisions(const struct hashmap_base *hb, const void *key);
double hashmap_base_collisions_mean(const struct hashmap_base *hb);
double hashmap_base_collisions_variance(const struct hashmap_base *hb);

size_t hashmap_hash_default(const void *data, size_t len);
size_t hashmap_hash_string(const char *key);
size_t hashmap_hash_string_i(const char *key);

