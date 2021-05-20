/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 00    Hash Tables */

#include "squid.h"
#include "hash.h"
#include "profiler/Profiler.h"

#include <cassert>
#include <cmath>
#include <cstdlib>
#include <cstring>
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#if HAVE_GNUMALLLOC_H
#include <gnumalloc.h>
#elif HAVE_MALLOC_H
#include <malloc.h>
#endif

unsigned int
hash_string(const void *data, unsigned int size)
{
    const unsigned char *s = static_cast<const unsigned char *>(data);
    unsigned int n = 0;
    unsigned int j = 0;
    unsigned int i = 0;
    while (*s) {
        ++j;
        n ^= 271 * *s;
        ++s;
    }
    i = n ^ (j * 271);
    return i % size;
}

/* the following function(s) were adapted from
 *    usr/src/lib/libc/db/hash_func.c, 4.4 BSD lite */

/* Hash function from Chris Torek. */
unsigned int
hash4(const void *data, unsigned int size)
{
    const char *key = static_cast<const char *>(data);
    size_t loop;
    unsigned int h;
    size_t len;

#define HASH4a   h = (h << 5) - h + *key++;
#define HASH4b   h = (h << 5) + h + *key++;
#define HASH4 HASH4b

    h = 0;
    len = strlen(key);
    loop = len >> 3;
    switch (len & (8 - 1)) {
    case 0:
        break;
    case 7:
        HASH4;
    /* FALLTHROUGH */
    case 6:
        HASH4;
    /* FALLTHROUGH */
    case 5:
        HASH4;
    /* FALLTHROUGH */
    case 4:
        HASH4;
    /* FALLTHROUGH */
    case 3:
        HASH4;
    /* FALLTHROUGH */
    case 2:
        HASH4;
    /* FALLTHROUGH */
    case 1:
        HASH4;
    }
    while (loop) {
        --loop;
        HASH4;
        HASH4;
        HASH4;
        HASH4;
        HASH4;
        HASH4;
        HASH4;
        HASH4;
    }
    return h % size;
}

hash_table::hash_table(HASHCMP *cmp_func, HASHHASH *hash_func, int hash_sz)
    : size(hash_sz), hash(hash_func), cmp(cmp_func) {
    buckets = static_cast<hash_link **>(xcalloc(size, sizeof(hash_link *)));
}

/**
 *  join a hash_link under its key lnk->key
 *  into the hash table.
 *
 *  It does not copy any data into the hash table, only links pointers.
 */
void
hash_table::hash_join(hash_link *lnk)
{
    int i;
    i = hash(lnk->key, this->size);
    lnk->next = buckets[i];
    buckets[i] = lnk;
    ++count;
}

/**
 *  hash_lookup - locates the item under the key 'k' in the hash table
 *  'hid'.  Returns a pointer to the hash bucket on success; otherwise
 *  returns NULL.
 */
hash_link *
hash_table::hash_lookup(const void *k)
{
    int b;
    PROF_start(hash_lookup);
    assert(k != NULL);
    b = hash(k, size);
    for (hash_link *walker = buckets[b]; walker != NULL; walker = walker->next) {
        if (cmp(k, walker->key) == 0) {
            PROF_stop(hash_lookup);
            return (walker);
        }
        assert(walker != walker->next);
    }
    PROF_stop(hash_lookup);
    return nullptr;
}

void
hash_table::hash_next_bucket()
{
    while (next == nullptr && ++current_slot < size)
        next = buckets[current_slot];
}

/**
 *  hash_first - initializes the hash table for the hash_next()
 *  function.
 */
void
hash_table::hash_first()
{
    assert(next == nullptr);
    current_slot = 0;
    next = buckets[current_slot];
    if (next == nullptr)
        hash_next_bucket();
}

/**
 *  hash_next - returns the next item in the hash table 'hid'.
 *  Otherwise, returns NULL on error or end of list.
 *
 *  MUST call hash_first() before hash_next().
 */
hash_link *
hash_table::hash_next()
{
    hash_link *p = next;
    if (p == nullptr)
        return nullptr;
    next = p->next;
    if (next == nullptr)
        hash_next_bucket();
    return p;
}

/**
 *  hash_last - resets hash traversal state to NULL
 *
 */
void
hash_table::hash_last()
{
    next = nullptr;
    current_slot = 0;
}

/**
 *  hash_remove_link - deletes the given hash_link node from the
 *  hash table 'hid'.  Does not free the item, only removes it
 *  from the list.
 *
 *  An assertion is triggered if the hash_link is not found in the
 *  list.
 */
void
hash_table::hash_remove_link(hash_link *hl)
{
    assert(hl != NULL);
    int i = hash(hl->key, size);
    for (hash_link **P = &buckets[i]; *P; P = &(*P)->next) {
        if (*P != hl)
            continue;
        *P = hl->next;
        if (next == hl) {
            next = hl->next;
            if (NULL == next)
                hash_next_bucket();
        }
        --count;
        return;
    }
    assert(0);
}

/**
 *  hash_get_bucket - returns the head item of the bucket
 *  in the hash table 'hid'. Otherwise, returns NULL on error.
 */
hash_link *
hash_table::hash_get_bucket(unsigned int bucket)
{
    if (bucket >= size)
        return nullptr;
    return buckets[bucket];
}

void
hash_table::hashFreeItems(HASHFREE * free_func)
{
    hash_link *l;
    int i = 0;
    hash_link **list = (hash_link **)xcalloc(count, sizeof(hash_link *));
    hash_first();
    while ((l = hash_next()) && i < count) {
        *(list + i) = l;
        ++i;
    }
    for (int j = 0; j < i; ++j)
        free_func(*(list + j));
    xfree(list);
}

hash_table::~hash_table()
{
    // xfree does nullptr check
    xfree(buckets);
}

static int hash_primes[] = {
    103,
    229,
    467,
    977,
    1979,
    4019,
    6037,
    7951,
    12149,
    16231,
    33493,
    65357
};

uint32_t
hash_table::hashPrime(uint32_t n)
{
    int I = sizeof(hash_primes) / sizeof(int);
    int best_prime = hash_primes[0];
    double min = fabs(log((double)n) - log((double)hash_primes[0]));
    double d;
    for (int i = 0; i < I; ++i) {
        d = fabs(log((double)n) - log((double)hash_primes[i]));
        if (d > min)
            continue;
        min = d;
        best_prime = hash_primes[i];
    }
    return best_prime;
}

#if USE_HASH_DRIVER
/**git
 *  hash-driver - Run with a big file as stdin to insert each line into the
 *  hash table, then prints the whole hash table, then deletes a random item,
 *  and prints the table again...
 */
int
main(void)
{
    hash_table *hid;
    LOCAL_ARRAY(char, buf, BUFSIZ);
    LOCAL_ARRAY(char, todelete, BUFSIZ);
    hash_link *walker = NULL;

    todelete[0] = '\0';
    printf("init\n");

    printf("creating hash table\n");
    if ((hid = hash_create((HASHCMP *) strcmp, 229, hash4)) < 0) {
        printf("hash_create error.\n");
        exit(EXIT_FAILURE);
    }
    printf("done creating hash table: %d\n", hid);

    std::mt19937 mt;
    xuniform_int_distribution<> dist(0,16);

    while (fgets(buf, BUFSIZ, stdin)) {
        buf[strlen(buf) - 1] = '\0';
        printf("Inserting '%s' for item %p to hash table: %d\n",
               buf, buf, hid);
        hash_insert(hid, xstrdup(buf), (void *) 0x12345678);
        if (dist(mt) == 0)
            strcpy(todelete, buf);
    }

    printf("walking hash table...\n");
    for (int i = 0, walker = hid->hash_first(); walker; walker = hash_next(hid)) {
        printf("item %5d: key: '%s' item: %p\n", i++, walker->key,
               walker->item);
    }
    printf("done walking hash table...\n");

    if (todelete[0]) {
        printf("deleting %s from %d\n", todelete, hid);
        if (hash_delete(hid, todelete))
            printf("hash_delete error\n");
    }
    printf("walking hash table...\n");
    for (int i = 0, walker = hash_first(hid); walker; walker = hash_next(hid)) {
        printf("item %5d: key: '%s' item: %p\n", i++, walker->key,
               walker->item);
    }
    printf("done walking hash table...\n");

    printf("driver finished.\n");
    return EXIT_SUCCESS;
}
#endif

