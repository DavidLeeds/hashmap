/*
 * Copyright (c) 2025 David Leeds <davidesleeds@gmail.com>
 *
 * Hashmap is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <hashmap.h>

#include <string>
#include <unordered_map>

#include <catch2/catch_test_macros.hpp>

using namespace std::literals;

static std::unordered_map<std::string, std::string> make_kvs(size_t count)
{
    std::unordered_map<std::string, std::string> input;

    for (size_t i = 0; i < count; ++i) {
        input.emplace("key" + std::to_string(i), "value" + std::to_string(i));
    }

    return input;
}

static void fill_map(auto *map, const std::unordered_map<std::string, std::string> &kvs)
{
    hashmap_clear(map);

    for (auto &[k, v] : kvs) {
        CAPTURE(k, v);
        REQUIRE(hashmap_put(map, k.c_str(), v.c_str()) == 0);
    }
}

TEST_CASE("hashmap", "[hashmap]") {
    /* Create a hashmap with string keys and values */
    HASHMAP(char, const char) map;
    hashmap_init(&map, hashmap_hash_string, strcmp);

    SECTION("initial state") {
        REQUIRE(hashmap_empty(&map));
        REQUIRE(hashmap_size(&map) == 0);

        /* No allocation is performed prior to use */
        REQUIRE(hashmap_capacity(&map) == 0);
    }

    SECTION("reserve") {
        /* Reserve space for at least 1000 elements */
        constexpr size_t CAPACITY = 1000;
        REQUIRE(hashmap_reserve(&map, CAPACITY) == 0);

        /* Check that at least the requested capacity was allocated */
        REQUIRE(hashmap_capacity(&map) >= CAPACITY);
    }

    SECTION("put and get") {
        /* Input is large enough to prompt rehashes */
        auto input = make_kvs(1000);

        for (auto &[k, v] : input) {
            CAPTURE(k, v);
            REQUIRE(hashmap_put(&map, k.c_str(), v.c_str()) == 0);
        }

        REQUIRE_FALSE(hashmap_empty(&map));
        REQUIRE(hashmap_size(&map) == input.size());

        for (auto &[k, v] : input) {
            CAPTURE(k, v);
            REQUIRE(hashmap_get(&map, k.c_str()) == v);
        }
    }

    SECTION("insert and get") {
        /* Input is large enough to prompt rehashes */
        auto input = make_kvs(1000);

        for (auto &[k, v] : input) {
            CAPTURE(k, v);
            REQUIRE(hashmap_insert(&map, k.c_str(), v.c_str(), nullptr) == 1);
        }

        REQUIRE_FALSE(hashmap_empty(&map));
        REQUIRE(hashmap_size(&map) == input.size());

        for (auto &[k, v] : input) {
            CAPTURE(k, v);
            REQUIRE(hashmap_get(&map, k.c_str()) == v);
        }
    }

    SECTION("put duplicate entry") {
        REQUIRE(hashmap_put(&map, "key1", "value1") == 0);
        REQUIRE(hashmap_put(&map, "key1", "value2") == -EEXIST);
        REQUIRE(hashmap_size(&map) == 1);
    }

    SECTION("insert duplicate entry") {
        const char *val1 = "value1";
        const char *val2 = "value2";
        const char *old_val;

        /* New key */
        old_val = "invalid";
        REQUIRE(hashmap_insert(&map, "key1", val1, &old_val) == 1);
        REQUIRE(old_val == nullptr);

        /* Existing key, same value */
        old_val = "invalid";
        REQUIRE(hashmap_insert(&map, "key1", val1, &old_val) == 0);
        REQUIRE(old_val == nullptr);

        /* Existing key, new value */
        old_val = "invalid";
        REQUIRE(hashmap_insert(&map, "key1", val2, &old_val) == 0);
        REQUIRE(old_val == val1);

        REQUIRE(hashmap_size(&map) == 1);
    }

    SECTION("get nonexistent entry") {
        /* Empty map */
        REQUIRE(hashmap_get(&map, "key1") == nullptr);

        /* Non-empty map */
        REQUIRE(hashmap_put(&map, "key2", "value2") == 0);
        REQUIRE(hashmap_get(&map, "key1") == nullptr);
    }


    SECTION("contains") {
        REQUIRE(hashmap_put(&map, "key1", "value1") == 0);

        REQUIRE(hashmap_contains(&map, "key1"));
        REQUIRE_FALSE(hashmap_contains(&map, "key2"));
    }

    SECTION("remove") {
        auto input = make_kvs(1000);

        fill_map(&map, input);

        size_t remaining = input.size();
        for (auto &[k, v] : input) {
            CAPTURE(k, v);

            REQUIRE(hashmap_size(&map) == remaining);
            REQUIRE(hashmap_get(&map, k.c_str()) == v);

            REQUIRE(hashmap_remove(&map, k.c_str()) == v);
            --remaining;

            REQUIRE(hashmap_get(&map, k.c_str()) == nullptr);
            REQUIRE(hashmap_size(&map) == remaining);
        }
    }

    SECTION("clear") {
        auto input = make_kvs(1000);

        size_t empty_capacity = hashmap_capacity(&map);

        fill_map(&map, input);

        size_t full_capacity = hashmap_capacity(&map);

        hashmap_clear(&map);

        size_t cleared_capacity = hashmap_capacity(&map);

        /* All elements removed */
        REQUIRE(hashmap_empty(&map));

        /* Should not reduce allocated space */
        REQUIRE(full_capacity > empty_capacity);
        REQUIRE(cleared_capacity == full_capacity);
    }

    SECTION("reset") {
        auto input = make_kvs(1000);

        size_t empty_capacity = hashmap_capacity(&map);

        fill_map(&map, input);

        size_t full_capacity = hashmap_capacity(&map);

        hashmap_reset(&map);

        size_t cleared_capacity = hashmap_capacity(&map);

        /* All elements removed */
        REQUIRE(hashmap_empty(&map));

        /* Should reset allocated space to a smaller initial size */
        REQUIRE(full_capacity > empty_capacity);
        REQUIRE(cleared_capacity >= empty_capacity);
        REQUIRE(cleared_capacity < full_capacity);
    }

    SECTION("iteration with iterator") {
        auto input = make_kvs(200);

        fill_map(&map, input);

        HASHMAP_ITER(map) iter = hashmap_iter(&map);

        size_t count = 0;
        do {
            REQUIRE(hashmap_iter_valid(&iter));

            const char *k = hashmap_iter_get_key(&iter);
            const char *v = hashmap_iter_get_data(&iter);

            REQUIRE(k != nullptr);
            REQUIRE(v != nullptr);

            REQUIRE(input.contains(k));
            REQUIRE(input.at(k) == v);

            ++count;
        } while (hashmap_iter_next(&iter));

        REQUIRE(count == input.size());
    }

    SECTION("iteration with iterator and remove all") {
        auto input = make_kvs(200);

        fill_map(&map, input);

        HASHMAP_ITER(map) iter = hashmap_iter(&map);

        size_t count = 0;

        while (hashmap_iter_valid(&iter)) {
            const char *k = hashmap_iter_get_key(&iter);
            const char *v = hashmap_iter_get_data(&iter);

            REQUIRE(k != nullptr);
            REQUIRE(v != nullptr);

            REQUIRE(input.contains(k));
            REQUIRE(input.at(k) == v);

            hashmap_iter_remove(&iter);

            ++count;
        }

        REQUIRE(count == input.size());
        REQUIRE(hashmap_empty(&map));
    }

    SECTION("iteration with iterator and remove some") {
        auto input = make_kvs(200);

        fill_map(&map, input);

        HASHMAP_ITER(map) iter = hashmap_iter(&map);

        size_t count = 0;

        while (hashmap_iter_valid(&iter)) {
            const char *k = hashmap_iter_get_key(&iter);
            const char *v = hashmap_iter_get_data(&iter);

            REQUIRE(k != nullptr);
            REQUIRE(v != nullptr);

            REQUIRE(input.contains(k));
            REQUIRE(input.at(k) == v);

            /* Remove every other entry */
            if (count % 2 == 0) {
                hashmap_iter_remove(&iter);
            } else {
                hashmap_iter_next(&iter);
            }

            ++count;
        }

        REQUIRE(count == input.size());
        REQUIRE(hashmap_size(&map) == input.size() / 2);
    }

    SECTION("find with iterator") {
        HASHMAP_ITER(map) iter;

        REQUIRE(hashmap_put(&map, "key1", "value1") == 0);

        /* Found */
        iter = hashmap_iter_find(&map, "key1");
        REQUIRE(hashmap_iter_valid(&iter));
        REQUIRE(hashmap_iter_get_key(&iter) == "key1"s);
        REQUIRE(hashmap_iter_get_data(&iter) == "value1"s);

        /* Not found */
        iter = hashmap_iter_find(&map, "key2");
        REQUIRE_FALSE(hashmap_iter_valid(&iter));
    }

    SECTION("iteration with foreach macros") {
        auto input = make_kvs(200);

        fill_map(&map, input);

        const char *key;
        const char *value;

        /* foreach */
        {
            size_t count = 0;
            hashmap_foreach(key, value, &map) {
                REQUIRE(key != nullptr);
                REQUIRE(value != nullptr);

                REQUIRE(input.contains(key));
                REQUIRE(input.at(key) == value);

                ++count;
            }
            REQUIRE(count == input.size());
        }

        /* foreach_key */
        {
            size_t count = 0;
            hashmap_foreach_key(key, &map) {
                REQUIRE(key != nullptr);
                REQUIRE(input.contains(key));
                ++count;
            }
            REQUIRE(count == input.size());
        }

        /* foreach_data */
        {
            size_t count = 0;
            hashmap_foreach_data(value, &map) {
                REQUIRE(value != nullptr);
                ++count;
            }
            REQUIRE(count == input.size());
        }
    }

    SECTION("iteration and removal with safe foreach macros") {
        auto input = make_kvs(200);

        const char *key;
        const char *value;
        const void *pos;

        /* safe foreach */
        {
            size_t count = 0;

            fill_map(&map, input);

            hashmap_foreach_safe(key, value, &map, pos) {
                REQUIRE(key != nullptr);
                REQUIRE(value != nullptr);

                REQUIRE(input.contains(key));
                REQUIRE(input.at(key) == value);

                /* Remove every other entry */
                if (count % 2 == 0) {
                    hashmap_remove(&map, key);
                }

                ++count;
            }
            REQUIRE(count == input.size());
            REQUIRE(hashmap_size(&map) == input.size() / 2);
        }

        /* safe foreach_key */
        {
            size_t count = 0;

            fill_map(&map, input);

            hashmap_foreach_key_safe(key, &map, pos) {
                REQUIRE(key != nullptr);
                REQUIRE(input.contains(key));

                /* Remove every other entry */
                if (count % 2 == 1) {
                    hashmap_remove(&map, key);
                }

                ++count;
            }
            REQUIRE(count == input.size());
            REQUIRE(hashmap_size(&map) == input.size() / 2);
        }

        /* safe foreach_data */
        {
            size_t count = 0;

            fill_map(&map, input);

            hashmap_foreach_data_safe(value, &map, pos) {
                REQUIRE(value != nullptr);
                ++count;
            }
            REQUIRE(count == input.size());
            REQUIRE(hashmap_size(&map) == input.size());
        }
    }

    SECTION("internal key allocation") {
        const char *key = "key1";
        auto strfree = [](char *k) { free(k); };

        hashmap_set_key_alloc_funcs(&map, strdup, strfree);

        REQUIRE(hashmap_put(&map, key, key) == 0);

        auto iter = hashmap_iter_find(&map, key);

        REQUIRE(hashmap_iter_valid(&iter));
        REQUIRE(hashmap_iter_get_key(&iter) != key);

        hashmap_iter_remove(&iter);
    }

    SECTION("bad hash functions") {
        auto cmp = [](const int *a, const int *b) -> int { return a - b; };

        static std::unordered_map<int, std::string> input;

        for (int i = 0; i < 200; ++i) {
            input.emplace(i, "value" + std::to_string(i));
        }

        /* Should be functional (albeit slower) when poor hash functions are used */
        auto test = [&](size_t (*hash)(const int *)) {
            HASHMAP(int, const char) int_map;
            hashmap_init(&int_map, hash, cmp);

            /* Put */
            for (auto &[k, v] : input) {
                CAPTURE(k, v);
                REQUIRE(hashmap_put(&int_map, &k, v.c_str()) == 0);
            }

            /* Get */
            for (auto &[k, v] : input) {
                CAPTURE(k, v);
                REQUIRE(hashmap_get(&int_map, &k) == v);
            }

            /* Remove */
            for (auto &[k, v] : input) {
                CAPTURE(k);
                REQUIRE(hashmap_remove(&int_map, &k) == v);
            }
        };

        SECTION("worst") {
            /* Hash lookup collides with every entry */
            auto hash = [](const int *) -> size_t { return 0; };

            test(hash);
        }

        SECTION("bad 1") {
            /* Could cause clustering depending on implementation */
            auto hash = [](const int *k) -> size_t { return *k; };

            test(hash);
        }

        SECTION("bad 2") {
            /* Could cause clustering depending on implementation */
            auto hash = [](const int *k) -> size_t { return *k + *k; };

            test(hash);
        }
    }

    hashmap_cleanup(&map);
}
