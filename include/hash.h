/*
 * $Id: hash.h,v 1.3 1998/09/23 20:13:46 wessels Exp $
 */

typedef void HASHFREE(void *);
typedef int HASHCMP(const void *, const void *);
typedef unsigned int HASHHASH(const void *, unsigned int);
typedef struct _hash_link hash_link;
typedef struct _hash_table hash_table;

struct _hash_link {
    char *key;
    hash_link *next;
};

struct _hash_table {
    hash_link **buckets;
    HASHCMP *cmp;
    HASHHASH *hash;
    unsigned int size;
    unsigned int current_slot;
    hash_link *next;
    int count;
};

extern hash_table *hash_create(HASHCMP *, int, HASHHASH *);
extern void hash_join(hash_table *, hash_link *);
extern void hash_remove_link(hash_table *, hash_link *);
extern int hashPrime(int n);
extern void *hash_lookup(hash_table *, const void *);
extern void hash_first(hash_table *);
extern void *hash_next(hash_table *);
extern void hash_last(hash_table *);
extern hash_link *hash_get_bucket(hash_table *, unsigned int);
extern void hashFreeMemory(hash_table *);
extern void hashFreeItems(hash_table *, HASHFREE *);
extern HASHHASH hash_string;
extern HASHHASH hash4;

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
