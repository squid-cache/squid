
/*
 * $Id$
 *
 * DEBUG: section 0     Hash Tables
 * AUTHOR: Harvest Derived
 *
 * SQUID Web Proxy Cache          http://www.squid-cache.org/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from
 *  the Internet community; see the CONTRIBUTORS file for full
 *  details.   Many organizations have provided support for Squid's
 *  development; see the SPONSORS file for full details.  Squid is
 *  Copyrighted (C) 2001 by the Regents of the University of
 *  California; see the COPYRIGHT file for full details.  Squid
 *  incorporates software developed and/or copyrighted by other
 *  sources; see the CREDITS file for full details.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111, USA.
 *
 */

#include "config.h"

#if HAVE_STDIO_H
#include <stdio.h>
#endif
#if HAVE_STDLIB_H
#include <stdlib.h>
#endif
#if HAVE_STRING_H
#include <string.h>
#endif
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#if HAVE_GNUMALLLOC_H
#include <gnumalloc.h>
#elif HAVE_MALLOC_H
#include <malloc.h>
#endif
#if HAVE_ASSERT_H
#include <assert.h>
#endif
#if HAVE_MATH_H
#include <math.h>
#endif

#include "hash.h"
#include "util.h"
#include "profiling.h"

static void hash_next_bucket(hash_table * hid);

unsigned int
hash_string(const void *data, unsigned int size)
{
    const char *s = data;
    unsigned int n = 0;
    unsigned int j = 0;
    unsigned int i = 0;
    while (*s) {
        j++;
        n ^= 271 * (unsigned) *s++;
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
    const char *key = data;
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
    while (loop--) {
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

/*
 *  hash_create - creates a new hash table, uses the cmp_func
 *  to compare keys.  Returns the identification for the hash table;
 *  otherwise returns a negative number on error.
 */
hash_table *
hash_create(HASHCMP * cmp_func, int hash_sz, HASHHASH * hash_func)
{
    hash_table *hid = xcalloc(1, sizeof(hash_table));
    if (!hash_sz)
        hid->size = (unsigned int) DEFAULT_HASH_SIZE;
    else
        hid->size = (unsigned int) hash_sz;
    /* allocate and null the buckets */
    hid->buckets = xcalloc(hid->size, sizeof(hash_link *));
    hid->cmp = cmp_func;
    hid->hash = hash_func;
    hid->next = NULL;
    hid->current_slot = 0;
    return hid;
}

/*
 *  hash_join - joins a hash_link under its key lnk->key
 *  into the hash table 'hid'.
 *
 *  It does not copy any data into the hash table, only links pointers.
 */
void
hash_join(hash_table * hid, hash_link * lnk)
{
    int i;
    i = hid->hash(lnk->key, hid->size);
    lnk->next = hid->buckets[i];
    hid->buckets[i] = lnk;
    hid->count++;
}

/*
 *  hash_lookup - locates the item under the key 'k' in the hash table
 *  'hid'.  Returns a pointer to the hash bucket on success; otherwise
 *  returns NULL.
 */
hash_link *
hash_lookup(hash_table * hid, const void *k)
{
    hash_link *walker;
    int b;
    PROF_start(hash_lookup);
    assert(k != NULL);
    b = hid->hash(k, hid->size);
    for (walker = hid->buckets[b]; walker != NULL; walker = walker->next) {
        if ((hid->cmp) (k, walker->key) == 0) {
            PROF_stop(hash_lookup);
            return (walker);
        }
        assert(walker != walker->next);
    }
    PROF_stop(hash_lookup);
    return NULL;
}

static void
hash_next_bucket(hash_table * hid)
{
    while (hid->next == NULL && ++hid->current_slot < hid->size)
        hid->next = hid->buckets[hid->current_slot];
}

/*
 *  hash_first - initializes the hash table for the hash_next()
 *  function.
 */
void
hash_first(hash_table * hid)
{
    assert(NULL == hid->next);
    hid->current_slot = 0;
    hid->next = hid->buckets[hid->current_slot];
    if (NULL == hid->next)
        hash_next_bucket(hid);
}

/*
 *  hash_next - returns the next item in the hash table 'hid'.
 *  Otherwise, returns NULL on error or end of list.
 *
 *  MUST call hash_first() before hash_next().
 */
hash_link *
hash_next(hash_table * hid)
{
    hash_link *this = hid->next;
    if (NULL == this)
        return NULL;
    hid->next = this->next;
    if (NULL == hid->next)
        hash_next_bucket(hid);
    return this;
}

/*
 *  hash_last - resets hash traversal state to NULL
 *
 */
void
hash_last(hash_table * hid)
{
    assert(hid != NULL);
    hid->next = NULL;
    hid->current_slot = 0;
}

/*
 *  hash_remove_link - deletes the given hash_link node from the
 *  hash table 'hid'.  Does not free the item, only removes it
 *  from the list.
 *
 *  An assertion is triggered if the hash_link is not found in the
 *  list.
 */
void
hash_remove_link(hash_table * hid, hash_link * hl)
{
    hash_link **P;
    int i;
    assert(hl != NULL);
    i = hid->hash(hl->key, hid->size);
    for (P = &hid->buckets[i]; *P; P = &(*P)->next) {
        if (*P != hl)
            continue;
        *P = hl->next;
        if (hid->next == hl) {
            hid->next = hl->next;
            if (NULL == hid->next)
                hash_next_bucket(hid);
        }
        hid->count--;
        return;
    }
    assert(0);
}

/*
 *  hash_get_bucket - returns the head item of the bucket
 *  in the hash table 'hid'. Otherwise, returns NULL on error.
 */
hash_link *
hash_get_bucket(hash_table * hid, unsigned int bucket)
{
    if (bucket >= hid->size)
        return NULL;
    return (hid->buckets[bucket]);
}

void
hashFreeItems(hash_table * hid, HASHFREE * free_func)
{
    hash_link *l;
    hash_link **list;
    int i = 0;
    int j;
    list = xcalloc(hid->count, sizeof(hash_link *));
    hash_first(hid);
    while ((l = hash_next(hid)) && i < hid->count) {
        *(list + i) = l;
        i++;
    }
    for (j = 0; j < i; j++)
        free_func(*(list + j));
    xfree(list);
}

void
hashFreeMemory(hash_table * hid)
{
    if (hid == NULL)
        return;
    if (hid->buckets)
        xfree(hid->buckets);
    xfree(hid);
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

int
hashPrime(int n)
{
    int I = sizeof(hash_primes) / sizeof(int);
    int i;
    int best_prime = hash_primes[0];
    double min = fabs(log((double) n) - log((double) hash_primes[0]));
    double d;
    for (i = 0; i < I; i++) {
        d = fabs(log((double) n) - log((double) hash_primes[i]));
        if (d > min)
            continue;
        min = d;
        best_prime = hash_primes[i];
    }
    return best_prime;
}

/*
 * return the key of a hash_link as a const string
 */
const char *
hashKeyStr(hash_link * hl)
{
    return (const char *) hl->key;
}


#ifdef USE_HASH_DRIVER
/*
 *  hash-driver - Run with a big file as stdin to insert each line into the
 *  hash table, then prints the whole hash table, then deletes a random item,
 *  and prints the table again...
 */
int
main(void)
{
    hash_table *hid;
    int i;
    LOCAL_ARRAY(char, buf, BUFSIZ);
    LOCAL_ARRAY(char, todelete, BUFSIZ);
    hash_link *walker = NULL;

    todelete[0] = '\0';
    printf("init\n");

    printf("creating hash table\n");
    if ((hid = hash_create((HASHCMP *) strcmp, 229, hash4)) < 0) {
        printf("hash_create error.\n");
        exit(1);
    }
    printf("done creating hash table: %d\n", hid);

    while (fgets(buf, BUFSIZ, stdin)) {
        buf[strlen(buf) - 1] = '\0';
        printf("Inserting '%s' for item %p to hash table: %d\n",
               buf, buf, hid);
        hash_insert(hid, xstrdup(buf), (void *) 0x12345678);
        if (random() % 17 == 0)
            strcpy(todelete, buf);
    }

    printf("walking hash table...\n");
    for (i = 0, walker = hash_first(hid); walker; walker = hash_next(hid)) {
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
    for (i = 0, walker = hash_first(hid); walker; walker = hash_next(hid)) {
        printf("item %5d: key: '%s' item: %p\n", i++, walker->key,
               walker->item);
    }
    printf("done walking hash table...\n");


    printf("driver finished.\n");
    exit(0);
}
#endif
