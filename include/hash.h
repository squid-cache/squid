/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_INCLUDE_HASH_H
#define SQUID_INCLUDE_HASH_H

typedef void HASHFREE(void *);
typedef int HASHCMP(const void *, const void *);
typedef unsigned int HASHHASH(const void *, unsigned int);

class hash_link {
public:
    hash_link() : key(nullptr), next(nullptr) {}
    void *key;
    hash_link *next;
};

class hash_table {
public:
    hash_link **buckets;
    HASHCMP *cmp;
    HASHHASH *hash;
    unsigned int size;
    unsigned int current_slot;
    hash_link *next;
    int count;
};

hash_table *hash_create(HASHCMP *, int, HASHHASH *);
void hash_join(hash_table *, hash_link *);
void hash_remove_link(hash_table *, hash_link *);
int hashPrime(int n);
hash_link *hash_lookup(hash_table *, const void *);
void hash_first(hash_table *);
hash_link *hash_next(hash_table *);
void hash_last(hash_table *);
hash_link *hash_get_bucket(hash_table *, unsigned int);
void hashFreeMemory(hash_table *);
void hashFreeItems(hash_table *, HASHFREE *);
HASHHASH hash_string;
HASHHASH hash4;
const char *hashKeyStr(const hash_link *);

/*
 *  Here are some good prime number choices.  It's important not to
 *  choose a prime number that is too close to exact powers of 2.
 *
 *  HASH_SIZE 103               // prime number < 128
 *  HASH_SIZE 229               // prime number < 256
 *  HASH_SIZE 467               // prime number < 512
 *  HASH_SIZE 977               // prime number < 1024
 *  HASH_SIZE 1979              // prime number < 2048
 *  HASH_SIZE 4019              // prime number < 4096
 *  HASH_SIZE 6037              // prime number < 6144
 *  HASH_SIZE 7951              // prime number < 8192
 *  HASH_SIZE 12149             // prime number < 12288
 *  HASH_SIZE 16231             // prime number < 16384
 *  HASH_SIZE 33493             // prime number < 32768
 *  HASH_SIZE 65357             // prime number < 65536
 */
#define  DEFAULT_HASH_SIZE 7951 /* prime number < 8192 */

#endif /* SQUID_INCLUDE_HASH_H */

