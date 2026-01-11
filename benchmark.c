/*
 * Simple benchmark to test hashmap performance optimizations
 */

#include <hashmap.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>

#define NUM_OPERATIONS 640000
#define KEY_SIZE       32

static double get_time_diff(struct timeval start, struct timeval end)
{
    return (end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec) / 1000000.0;
}

static void generate_random_key(char *key, int length)
{
    const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    for (int i = 0; i < length - 1; i++) {
        key[i] = charset[rand() % (sizeof(charset) - 1)];
    }
    key[length - 1] = '\0';
}

int main()
{
    HASHMAP(char, int) map;
    struct timeval start, end;
    char (*keys)[KEY_SIZE];
    int *values;
    double insert_time, lookup_time, remove_time;

    printf("Hashmap Performance Benchmark\n");
    printf("=============================\n");
    printf("Operations: %d\n", NUM_OPERATIONS);
    printf("Key size: %d bytes\n\n", KEY_SIZE);

    /* Allocate memory for keys and values on the heap */
    keys = malloc(NUM_OPERATIONS * KEY_SIZE * sizeof(char));
    values = malloc(NUM_OPERATIONS * sizeof(int));
    if (!keys || !values) {
        fprintf(stderr, "Failed to allocate memory for benchmark data\n");
        return 1;
    }

    /* Initialize hashmap */
    hashmap_init(&map, hashmap_hash_string, strcmp);

    /* Pre-generate keys and values */
    srand(42); /* Fixed seed for reproducible results */
    for (int i = 0; i < NUM_OPERATIONS; i++) {
        generate_random_key(keys[i], KEY_SIZE);
        values[i] = i;
    }

    /* Reserve space to avoid rehashing during benchmark */
    hashmap_reserve(&map, NUM_OPERATIONS);

    /* Benchmark insertions */
    printf("Benchmarking insertions...\n");
    gettimeofday(&start, NULL);
    for (int i = 0; i < NUM_OPERATIONS; i++) {
        hashmap_put(&map, keys[i], &values[i]);
    }
    gettimeofday(&end, NULL);
    insert_time = get_time_diff(start, end);

    printf("Insert time: %.3f seconds\n", insert_time);
    printf("Insert rate: %.0f ops/sec\n", NUM_OPERATIONS / insert_time);
    printf("Load factor: %.3f\n", hashmap_base_load_factor(&map.map_base));
    printf("Mean collisions: %.3f\n", hashmap_base_collisions_mean(&map.map_base));
    printf("\n");

    /* Benchmark lookups */
    printf("Benchmarking lookups...\n");
    gettimeofday(&start, NULL);
    for (int i = 0; i < NUM_OPERATIONS; i++) {
        volatile int *result = hashmap_get(&map, keys[i]);
        (void)result; /* Prevent optimization */
    }
    gettimeofday(&end, NULL);
    lookup_time = get_time_diff(start, end);

    printf("Lookup time: %.3f seconds\n", lookup_time);
    printf("Lookup rate: %.0f ops/sec\n", NUM_OPERATIONS / lookup_time);
    printf("\n");

    /* Benchmark removals */
    printf("Benchmarking removals...\n");
    gettimeofday(&start, NULL);
    for (int i = 0; i < NUM_OPERATIONS; i++) {
        hashmap_remove(&map, keys[i]);
    }
    gettimeofday(&end, NULL);
    remove_time = get_time_diff(start, end);

    printf("Remove time: %.3f seconds\n", remove_time);
    printf("Remove rate: %.0f ops/sec\n", NUM_OPERATIONS / remove_time);
    printf("\n");

    /* Summary */
    printf("Summary:\n");
    printf("Total time: %.3f seconds\n", insert_time + lookup_time + remove_time);
    printf("Average operation time: %.3f microseconds\n",
           (insert_time + lookup_time + remove_time) * 1000000 / (3 * NUM_OPERATIONS));

    hashmap_cleanup(&map);

    /* Free allocated memory */
    free(keys);
    free(values);

    return 0;
}