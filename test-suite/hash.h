#define  DEFAULT_HASH_SIZE 7951     
typedef unsigned int HASHHASH(const void *, unsigned int);
struct _hash_link {  
    char *key;
    struct _hash_link *next;
    void *item;
};
typedef int HASHCMP(const void *, const void *);

typedef struct _hash_link hash_link;

struct _hash_table {
    int valid;
    hash_link **buckets;
    HASHCMP *cmp;
    HASHHASH *hash;
    unsigned int size;
    unsigned int current_slot;
    hash_link *current_ptr;
};  
typedef struct _hash_table hash_table;

extern int hash_links_allocated;
extern int store_hash_buckets;        /* 0 */
extern hash_table *store_table;       /* NULL */
extern hash_table *hash_create(HASHCMP *, int, HASHHASH *);
extern void hash_insert(hash_table *, const char *, void *);
extern int hash_delete(hash_table *, const char *);
int hash_delete_link(hash_table *, hash_link *);
int hash_unlink(hash_table *,hash_link *, int);
void hash_join(hash_table *, hash_link *);
int hash_remove_link(hash_table *, hash_link *);
hash_link *hash_lookup(hash_table *, const void *);
hash_link *hash_first(hash_table *);
hash_link *hash_next(hash_table *);
hash_link *hash_get_bucket(hash_table *, unsigned int);
void hashFreeMemory(hash_table *);
HASHHASH hash_string;
HASHHASH hash_url;
HASHHASH hash4;
