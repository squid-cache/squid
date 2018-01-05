/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 00    Hash Tables */

#include "squid.h"

#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#if HAVE_CTYPE_H
#include <ctype.h>
#endif
#if HAVE_STRINGS_H
#include <strings.h>
#endif
#if HAVE_ASSERT_H
#include <assert.h>
#endif

#include "hash.h"

#undef free
extern void my_free(char *, int, void *);

#define free(a) my_free(__FILE__, __LINE__, a)

extern void print_stats();
/*
 *  hash_url() - Returns a well-distributed hash function for URLs.
 *  The best way is to sum up the last half of the string.
 *  Adapted from code written by Mic Bowman.  -Darren
 *  Generates a standard deviation = 15.73
 */
unsigned int
hash_url(const void *data, unsigned int size)
{
    const char *s = data;
    unsigned int i, j, n;
    j = strlen(s);
    for (i = j / 2, n = 0; i < j; i++)
        n ^= 271 * (unsigned) s[i];
    i = n ^ (j * 271);
    return i % size;
}

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

/* the following 4 functions were adapted from
 *    usr/src/lib/libc/db/hash_func.c, 4.4 BSD lite */

/*
 * HASH FUNCTIONS
 *
 * Assume that we've already split the bucket to which this key hashes,
 * calculate that bucket, and check that in fact we did already split it.
 *
 * This came from ejb's hsearch.
 */

#define PRIME1      37
#define PRIME2      1048583

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
    loop = (len + 8 - 1) >> 3;
    switch (len & (8 - 1)) {
    case 0:
        do {
            HASH4;
        /* FALLTHROUGH */
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
        } while (--loop);
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
    hash_table *hid = calloc(1, sizeof(hash_table));
    if (!hash_sz)
        hid->size = (unsigned int) DEFAULT_HASH_SIZE;
    else
        hid->size = (unsigned int) hash_sz;
    /* allocate and null the buckets */
    hid->buckets = calloc(hid->size, sizeof(hash_link *));
    hid->cmp = cmp_func;
    hid->hash = hash_func;
    hid->current_ptr = NULL;
    hid->current_slot = 0;
    return hid;
}

/*
 *  hash_insert - inserts the given item 'item' under the given key 'k'
 *  into the hash table 'hid'.  Returns non-zero on error; otherwise,
 *  returns 0 and inserts the item.
 *
 *  It does not copy any data into the hash table, only pointers.
 */
void
hash_insert(hash_table * hid, const char *k, void *item)
{
    int i;
    hash_link *new;
    assert(k != NULL);
    /* Add to the given hash table 'hid' */
    new = calloc(1, sizeof(hash_link));
    if (!new) {
        fprintf(stderr, "calloc failed!\n");
        print_stats();
        exit(1);
    }
    new->item = item;
    new->key = (char *) k;
    i = hid->hash(k, hid->size);
    new->next = hid->buckets[i];
    hid->buckets[i] = new;
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
    assert(k != NULL);
    b = hid->hash(k, hid->size);
    for (walker = hid->buckets[b]; walker != NULL; walker = walker->next) {
        if ((hid->cmp) (k, walker->key) == 0)
            return (walker);
        assert(walker != walker->next);
    }
    return NULL;
}

/*
 *  hash_first - returns the first item in the hash table 'hid'.
 *  Otherwise, returns NULL on error.
 */
hash_link *
hash_first(hash_table * hid)
{
    int i;

    for (i = 0; i < hid->size; i++) {
        hid->current_slot = i;
        if (hid->buckets[i] != NULL)
            return (hid->current_ptr = hid->buckets[i]);
    }
    return NULL;
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
    int i;

    if (hid->current_ptr != NULL) {
        hid->current_ptr = hid->current_ptr->next;
        if (hid->current_ptr != NULL)
            return (hid->current_ptr);  /* next item */
    }
    /* find next bucket */
    for (i = hid->current_slot + 1; i < hid->size; i++) {
        hid->current_slot = i;
        if (hid->buckets[i] != NULL)
            return (hid->current_ptr = hid->buckets[i]);
    }
    return NULL;        /* end of list */
}

int
hash_delete(hash_table * hid, const char *key)
{
    return hash_delete_link(hid, hash_lookup(hid, key));
}

/*
 *  hash_delete_link - deletes the given hash_link node from the
 *  hash table 'hid'. If FreeLink then free the given hash_link.
 *
 *  On success, it returns 0 and deletes the link; otherwise,
 *  returns non-zero on error.
 */
int
hash_unlink(hash_table * hid, hash_link * hl, int FreeLink)
{
    hash_link *walker, *prev;
    int i;
    if (hl == NULL)
        return -1;
    i = hid->hash(hl->key, hid->size);
    for (prev = NULL, walker = hid->buckets[i];
            walker != NULL; prev = walker, walker = walker->next) {
        if (walker == hl) {
            if (prev == NULL) { /* it's the head */
                hid->buckets[i] = walker->next;
            } else {
                prev->next = walker->next;  /* skip it */
            }
            /* fix walker state if needed */
            if (walker == hid->current_ptr)
                hid->current_ptr = walker->next;
            if (FreeLink) {
                if (walker) {
                    free(walker);
                }
            }
            return 0;
        }
    }
    return 1;
}

/* take link off and free link node */
int
hash_delete_link(hash_table * hid, hash_link * hl)
{
    return (hash_unlink(hid, hl, 1));
}

/* take link off only */
int
hash_remove_link(hash_table * hid, hash_link * hl)
{
    return (hash_unlink(hid, hl, 0));
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
hashFreeMemory(hash_table * hid)
{
    if (hid->buckets);
    free(hid->buckets);
    if (hid)
        free(hid);
}

#if USE_HASH_DRIVER
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
    if ((hid = hash_create(strcmp, 229, hash_string)) < 0) {
        printf("hash_create error.\n");
        exit(1);
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

