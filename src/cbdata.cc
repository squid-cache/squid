
/* DEBUG: 45 */

#include "squid.h"

static hash_table *htable = NULL;

typedef struct _cbdata {
    void *key;
    struct _cbdata *next;
    int valid;
    int locks;
} cbdata;

static HASHCMP cbdata_cmp;
static HASHHASH cbdata_hash;

static int
cbdata_cmp(const char *p1, const char *p2)
{
    return p1 - p2;
}

static unsigned int
cbdata_hash(const char *p, unsigned int mod)
{
    return ((unsigned long) p >> 8) % mod;
}


void
cbdataInit(void)
{
    debug(45, 3) ("cbdataInit\n");
    htable = hash_create(cbdata_cmp, 1 << 8, cbdata_hash);
}

void
cbdataAdd(void *p)
{
    cbdata *c;
    assert(p);
    debug(45, 3) ("cbdataAdd: %p\n", p);
    assert(htable != NULL);
    assert(hash_lookup(htable, p) == NULL);
    c = xcalloc(1, sizeof(cbdata));
    c->key = p;
    c->valid = 1;
    hash_join(htable, (hash_link *) c);
}

void
cbdataFree(void *p)
{
    cbdata *c = (cbdata *) hash_lookup(htable, p);
    assert(p);
    debug(45, 3) ("cbdataFree: %p\n", p);
    assert(c != NULL);
    c->valid = 0;
    if (c->locks) {
	debug(45, 3) ("cbdataFree: %p has %d locks, not freeing\n",
		p, c->locks);
	return;
    }
    hash_remove_link(htable, (hash_link *) c);
    xfree(c);
    debug(45, 3) ("cbdataFree: freeing %p\n", p);
    xfree(p);
}

void
cbdataLock(void *p)
{
    cbdata *c;
    if (p == NULL)
	return;
    c = (cbdata *) hash_lookup(htable, p);
    debug(45, 3) ("cbdataLock: %p\n", p);
    assert(c != NULL);
    c->locks++;
}

void
cbdataUnlock(void *p)
{
    cbdata *c;
    if (p == NULL)
	return;
    c = (cbdata *) hash_lookup(htable, p);
    debug(45, 3) ("cbdataUnlock: %p\n", p);
    assert(c != NULL);
    assert(c->locks > 0);
    c->locks--;
    if (c->valid || c->locks)
	return;
    hash_remove_link(htable, (hash_link *) c);
    xfree(c);
    debug(45, 3) ("cbdataUnlock: Freeing %p\n", p);
    xfree(p);
}

int
cbdataValid(void *p)
{
    cbdata *c;
    if (p == NULL)
	return 0;
    c = (cbdata *) hash_lookup(htable, p);
    debug(45, 3) ("cbdataValid: %p\n", p);
    assert(c != NULL);
    assert(c->locks > 0);
    return c->valid;
}


void
cbdataDump(StoreEntry * sentry)
{
    hash_link *hptr;
    cbdata *c;
    for (hptr = hash_first(htable); hptr; hptr = hash_next(htable)) {
	c = (cbdata *) hptr;
	storeAppendPrintf(sentry, "%20p %10s %d locks\n",
	    c->key,
	    c->valid ? "VALID" : "NOT VALID",
	    c->locks);
    }
}
