/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_HASH_H
#define SQUID_HASH_H

/*
 * for hash_table size, it is recommended to use
 * hash_table::hashPrime(desired_size) for optimal performance
 */
#define DEFAULT_HASH_SIZE 7951 /* prime number < 8192 */

typedef void HASHFREE(void *);
typedef int HASHCMP(const void *, const void *);
typedef unsigned int HASHHASH(const void *, unsigned int);

class hash_link {
public:
    hash_link() {}
    const char *hashKeyStr() const {
        return static_cast<const char *>(key);
    };
    void *key = nullptr;
    hash_link *next = nullptr;
};

class hash_table {
public:
    hash_table(HASHCMP *cmp_func, HASHHASH *hash_func,
               int hash_sz = DEFAULT_HASH_SIZE);
    ~hash_table();
    void hash_join(hash_link *);
    void hash_remove_link(hash_link *);
    static uint32_t hashPrime(uint32_t n);
    hash_link *hash_lookup(const void *);
    hash_link *hash_next();
    void hash_last();
    void hash_first();
    hash_link *hash_get_bucket(unsigned int);
    void hashFreeItems(HASHFREE *);
    int hash_count() const { return count; }

private:
    int count = 0;
    hash_link *next = nullptr;
    unsigned int size;
    hash_link **buckets = nullptr;
    unsigned int current_slot = 0;
    HASHHASH *hash;
    HASHCMP *cmp;
    void hash_next_bucket();
};

SQUIDCEXTERN HASHHASH hash_string;
SQUIDCEXTERN HASHHASH hash4;

#endif /* SQUID_HASH_H */

