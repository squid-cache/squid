
/*
 * $Id: cbdata.cc,v 1.48 2002/10/24 22:59:29 adrian Exp $
 *
 * DEBUG: section 45    Callback Data Registry
 * ORIGINAL AUTHOR: Duane Wessels
 * Modified by Moez Mahfoudh (08/12/2000)
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

/*
 * These routines manage a set of registered callback data pointers.
 * One of the easiest ways to make Squid coredump is to issue a 
 * callback to for some data structure which has previously been
 * freed.  With these routines, we register (add) callback data
 * pointers, lock them just before registering the callback function,
 * validate them before issuing the callback, and then free them
 * when finished.
 */

#include "squid.h"
#include "Store.h"

static int cbdataCount = 0;
#if CBDATA_DEBUG
dlink_list cbdataEntries;
#endif

typedef struct _cbdata {
    int valid;
    int locks;
    int type;
#if CBDATA_DEBUG
    dlink_node link;
    const char *file;
    int line;
#endif
    long y;			/* cookie used while debugging */
    union {
	void *pointer;
	double double_float;
	int integer;
    } data;
} cbdata;

static OBJH cbdataDump;

struct CBDataIndex {
    MemPool *pool;
    FREE *free_func;
}     *cbdata_index = NULL;
int cbdata_types = 0;

#define OFFSET_OF(type, member) ((int)(char *)&((type *)0L)->member)
#define CBDATA_COOKIE	(long)0xDEADBEEF
#define CBDATA_CHECK(c) assert(c->y == ((long)c ^ CBDATA_COOKIE))

static void
cbdataInternalInitType(cbdata_type type, const char *name, int size, FREE * free_func)
{
    char *label;
    if (type >= cbdata_types) {
	cbdata_index = (CBDataIndex *)xrealloc(cbdata_index, (type + 1) * sizeof(*cbdata_index));
	memset(&cbdata_index[cbdata_types], 0,
	    (type + 1 - cbdata_types) * sizeof(*cbdata_index));
	cbdata_types = type + 1;
    }
    if (cbdata_index[type].pool)
	return;
    label = (char *)xmalloc(strlen(name) + 20);
    snprintf(label, strlen(name) + 20, "cbdata %s (%d)", name, (int) type);
    assert(OFFSET_OF(cbdata, data) == (sizeof(cbdata) - sizeof(((cbdata *) NULL)->data)));
    cbdata_index[type].pool = memPoolCreate(label, size + OFFSET_OF(cbdata, data));
    cbdata_index[type].free_func = free_func;
}

cbdata_type
cbdataInternalAddType(cbdata_type type, const char *name, int size, FREE * free_func)
{
    if (type)
	return type;
    type = (cbdata_type)cbdata_types;
    cbdataInternalInitType(type, name, size, free_func);
    return type;
}

void
cbdataInit(void)
{
    debug(45, 3) ("cbdataInit\n");
    cachemgrRegister("cbdata",
	"Callback Data Registry Contents",
	cbdataDump, 0, 1);
#define CREATE_CBDATA(type) cbdataInternalInitType(CBDATA_##type, #type, sizeof(type), NULL)
#define CREATE_CBDATA_FREE(type, free_func) cbdataInternalInitType(CBDATA_##type, #type, sizeof(type), free_func)
    /* XXX
     * most of these should be moved out to their respective module.
     */
    CREATE_CBDATA(acl_access);
    CREATE_CBDATA(aclCheck_t);
    CREATE_CBDATA(clientHttpRequest);
    CREATE_CBDATA(ConnStateData);
    CREATE_CBDATA(ErrorState);
    CREATE_CBDATA(FwdState);
    CREATE_CBDATA(generic_cbdata);
    CREATE_CBDATA(helper);
    CREATE_CBDATA(helper_server);
    CREATE_CBDATA(statefulhelper);
    CREATE_CBDATA(helper_stateful_server);
    CREATE_CBDATA_FREE(peer, peerDestroy);
    CREATE_CBDATA(ps_state);
    CREATE_CBDATA(RemovalPolicy);
    CREATE_CBDATA(RemovalPolicyWalker);
    CREATE_CBDATA(RemovalPurgeWalker);
}

void *
#if CBDATA_DEBUG
cbdataInternalAllocDbg(cbdata_type type, const char *file, int line)
#else
cbdataInternalAlloc(cbdata_type type)
#endif
{
    cbdata *p;
    assert(type > 0 && type < cbdata_types);
    p = (cbdata *)memPoolAlloc(cbdata_index[type].pool);
    p->type = type;
    p->valid = 1;
    p->locks = 0;
#if CBDATA_DEBUG
    p->file = file;
    p->line = line;
#endif
    p->y = (long) p ^ CBDATA_COOKIE;
    cbdataCount++;

#if CBDATA_DEBUG
    dlinkAdd(p, &p->link, &cbdataEntries);
    debug(45, 3) ("cbdataAlloc: %p %s:%d\n", &p->data, file, line);
#endif
    return (void *) &p->data;
}

void *
#if CBDATA_DEBUG
cbdataInternalFreeDbg(void *p, const char *file, int line)
#else
cbdataInternalFree(void *p)
#endif
{
    cbdata *c;
    FREE *free_func;
    c = (cbdata *) (((char *) p) - OFFSET_OF(cbdata, data));
#if CBDATA_DEBUG
    debug(45, 3) ("cbdataFree: %p %s:%d\n", p, file, line);
#else
    debug(45, 3) ("cbdataFree: %p\n", p);
#endif
    CBDATA_CHECK(c);
    c->valid = 0;
    if (c->locks) {
	debug(45, 3) ("cbdataFree: %p has %d locks, not freeing\n",
	    p, c->locks);
	return NULL;
    }
    cbdataCount--;
    debug(45, 3) ("cbdataFree: Freeing %p\n", p);
#if CBDATA_DEBUG
    dlinkDelete(&c->link, &cbdataEntries);
#endif
    free_func = cbdata_index[c->type].free_func;
    if (free_func)
	free_func((void *) p);
    memPoolFree(cbdata_index[c->type].pool, c);
    return NULL;
}

void
#if CBDATA_DEBUG
cbdataInternalLockDbg(const void *p, const char *file, int line)
#else
cbdataInternalLock(const void *p)
#endif
{
    cbdata *c;
    if (p == NULL)
	return;
    c = (cbdata *) (((char *) p) - OFFSET_OF(cbdata, data));
#if CBDATA_DEBUG
    debug(45, 3) ("cbdataLock: %p=%d %s:%d\n", p, c ? c->locks + 1 : -1, file, line);
#else
    debug(45, 3) ("cbdataLock: %p=%d\n", p, c ? c->locks + 1 : -1);
#endif
    CBDATA_CHECK(c);
    assert(c->locks < 65535);
    c->locks++;
}

void
#if CBDATA_DEBUG
cbdataInternalUnlockDbg(const void *p, const char *file, int line)
#else
cbdataInternalUnlock(const void *p)
#endif
{
    cbdata *c;
    FREE *free_func;
    if (p == NULL)
	return;
    c = (cbdata *) (((char *) p) - OFFSET_OF(cbdata, data));
#if CBDATA_DEBUG
    debug(45, 3) ("cbdataUnlock: %p=%d %s:%d\n", p, c ? c->locks - 1 : -1, file, line);
#else
    debug(45, 3) ("cbdataUnlock: %p=%d\n", p, c ? c->locks - 1 : -1);
#endif
    CBDATA_CHECK(c);
    assert(c != NULL);
    assert(c->locks > 0);
    c->locks--;
    if (c->valid || c->locks)
	return;
    cbdataCount--;
    debug(45, 3) ("cbdataUnlock: Freeing %p\n", p);
#if CBDATA_DEBUG
    dlinkDelete(&c->link, &cbdataEntries);
#endif
    free_func = cbdata_index[c->type].free_func;
    if (free_func)
	free_func((void *) p);
    memPoolFree(cbdata_index[c->type].pool, c);
}

int
cbdataReferenceValid(const void *p)
{
    cbdata *c;
    if (p == NULL)
	return 1;		/* A NULL pointer cannot become invalid */
    debug(45, 3) ("cbdataReferenceValid: %p\n", p);
    c = (cbdata *) (((char *) p) - OFFSET_OF(cbdata, data));
    CBDATA_CHECK(c);
    assert(c->locks > 0);
    return c->valid;
}

int
#if CBDATA_DEBUG
cbdataInternalReferenceDoneValidDbg(void **pp, void **tp, const char *file, int line)
#else
cbdataInternalReferenceDoneValid(void **pp, void **tp)
#endif
{
    void *p = (void *) *pp;
    int valid = cbdataReferenceValid(p);
    *pp = NULL;
#if CBDATA_DEBUG
    cbdataInternalUnlockDbg(p, file, line);
#else
    cbdataInternalUnlock(p);
#endif
    if (valid) {
	*tp = p;
	return 1;
    } else {
	*tp = NULL;
	return 0;
    }
}


static void
cbdataDump(StoreEntry * sentry)
{
#if CBDATA_DEBUG
    dlink_node *n;
    cbdata *p;
    int i;
#endif
    storeAppendPrintf(sentry, "%d cbdata entries\n", cbdataCount);
#if CBDATA_DEBUG
    storeAppendPrintf(sentry, "Pointer\tType\tLocks\tAllocated by\n");
    for (n = cbdataEntries.head; n; n = n->next) {
	p = (cbdata *)n->data;
	storeAppendPrintf(sentry, "%c%p\t%d\t%d\t%20s:%-5d\n", p->valid ? ' ' : '!', &p->data, p->type, p->locks, p->file, p->line);
    }
    storeAppendPrintf(sentry, "\n");
    storeAppendPrintf(sentry, "types\tsize\tallocated\ttotal\n");
    for (i = 1; i < cbdata_types; i++) {
	MemPool *pool = cbdata_index[i].pool;
	if (pool) {
	    int obj_size = pool->obj_size - OFFSET_OF(cbdata, data);
	    storeAppendPrintf(sentry, "%s\t%d\t%d\t%d\n", pool->label + 7, obj_size, pool->meter.inuse.level, obj_size * pool->meter.inuse.level);
	}
    }
#else
    storeAppendPrintf(sentry, "detailed allocation information only available when compiled with CBDATA_DEBUG\n");
#endif
    storeAppendPrintf(sentry, "\nsee also \"Memory utilization\" for detailed per type statistics\n");
}
