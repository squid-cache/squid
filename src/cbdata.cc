
/*
 * $Id: cbdata.cc,v 1.42 2001/10/17 19:43:39 hno Exp $
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
 * 
 * In terms of time, the sequence goes something like this:
 * 
 * foo = cbdataAlloc(sizeof(foo),NULL);
 * ...
 * some_blocking_operation(..., callback_func, foo);
 *   cbdataLock(foo);
 *   ...
 *   some_blocking_operation_completes()
 *   if (cbdataValid(foo))
 *   callback_func(..., foo)
 *   cbdataUnlock(foo);
 * ...
 * cbdataFree(foo);
 * 
 * The nice thing is that, we do not need to require that Unlock
 * occurs before Free.  If the Free happens first, then the 
 * callback data is marked invalid and the callback will never
 * be made.  When we Unlock and the lock count reaches zero,
 * we free the memory if it is marked invalid.
 */

#include "squid.h"

static int cbdataCount = 0;

typedef struct _cbdata {
    int valid;
    int locks;
    int type;
#if CBDATA_DEBUG
    const char *file;
    int line;
#endif
    void *y;			/* cookie used while debugging */
    union {
	void *pointer;
	double double_float;
	int integer;
    } data;
} cbdata;

static OBJH cbdataDump;

struct {
    MemPool *pool;
    FREE *free_func;
}     *cbdata_index = NULL;
int cbdata_types = 0;

#define OFFSET_OF(type, member) ((int)(char *)&((type *)0L)->member)

void
cbdataInitType(cbdata_type type, const char *name, int size, FREE * free_func)
{
    char *label;
    if (type >= cbdata_types) {
	cbdata_index = xrealloc(cbdata_index, (type + 1) * sizeof(*cbdata_index));
	memset(&cbdata_index[cbdata_types], 0,
	    (type + 1 - cbdata_types) * sizeof(*cbdata_index));
	cbdata_types = type + 1;
    }
    if (cbdata_index[type].pool)
	return;
    label = xmalloc(strlen(name) + 20);
    snprintf(label, strlen(name) + 20, "cbdata %s (%d)", name, (int) type);
    assert(OFFSET_OF(cbdata, data) == (sizeof(cbdata) - sizeof(((cbdata *) NULL)->data)));
    cbdata_index[type].pool = memPoolCreate(label, size + OFFSET_OF(cbdata, data));
    cbdata_index[type].free_func = free_func;
}

cbdata_type
cbdataAddType(cbdata_type type, const char *name, int size, FREE * free_func)
{
    if (type)
	return type;
    type = cbdata_types;
    cbdataInitType(type, name, size, free_func);
    return type;
}

void
cbdataInit(void)
{
    debug(45, 3) ("cbdataInit\n");
    cachemgrRegister("cbdata",
	"Callback Data Registry Contents",
	cbdataDump, 0, 1);
#define CREATE_CBDATA(type) cbdataInitType(CBDATA_##type, #type, sizeof(type), NULL)
#define CREATE_CBDATA_FREE(type, free_func) cbdataInitType(CBDATA_##type, #type, sizeof(type), free_func)
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
    CREATE_CBDATA(HttpStateData);
    CREATE_CBDATA_FREE(peer, peerDestroy);
    CREATE_CBDATA(ps_state);
    CREATE_CBDATA(RemovalPolicy);
    CREATE_CBDATA(RemovalPolicyWalker);
    CREATE_CBDATA(RemovalPurgeWalker);
    CREATE_CBDATA(store_client);
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
    p = memPoolAlloc(cbdata_index[type].pool);
    p->type = type;
    p->valid = 1;
    p->locks = 0;
#if CBDATA_DEBUG
    p->file = file;
    p->line = line;
#endif
    p->y = p;
    cbdataCount++;

    return (void *) &p->data;
}

void *
cbdataInternalFree(void *p)
{
    cbdata *c;
    FREE *free_func;
    debug(45, 3) ("cbdataFree: %p\n", p);
    c = (cbdata *) (((char *) p) - OFFSET_OF(cbdata, data));
    assert(c->y == c);
    c->valid = 0;
    if (c->locks) {
	debug(45, 3) ("cbdataFree: %p has %d locks, not freeing\n",
	    p, c->locks);
	return NULL;
    }
    cbdataCount--;
    debug(45, 3) ("cbdataFree: Freeing %p\n", p);
    free_func = cbdata_index[c->type].free_func;
    if (free_func)
	free_func((void *) p);
    memPoolFree(cbdata_index[c->type].pool, c);
    return NULL;
}

int
cbdataLocked(const void *p)
{
    cbdata *c;
    assert(p);
    c = (cbdata *) (((char *) p) - OFFSET_OF(cbdata, data));
    assert(c->y == c);
    debug(45, 3) ("cbdataLocked: %p = %d\n", p, c->locks);
    assert(c != NULL);
    return c->locks;
}

void
#if CBDATA_DEBUG
cbdataLockDbg(const void *p, const char *file, int line)
#else
cbdataLock(const void *p)
#endif
{
    cbdata *c;
    if (p == NULL)
	return;
    c = (cbdata *) (((char *) p) - OFFSET_OF(cbdata, data));
    assert(c->y == c);
    debug(45, 3) ("cbdataLock: %p\n", p);
    assert(c != NULL);
    c->locks++;
#if CBDATA_DEBUG
    c->file = file;
    c->line = line;
#endif
}

void
#if CBDATA_DEBUG
cbdataUnlockDbg(const void *p, const char *file, int line)
#else
cbdataUnlock(const void *p)
#endif
{
    cbdata *c;
    FREE *free_func;
    if (p == NULL)
	return;
    c = (cbdata *) (((char *) p) - OFFSET_OF(cbdata, data));
    assert(c->y == c);
    debug(45, 3) ("cbdataUnlock: %p\n", p);
    assert(c != NULL);
    assert(c->locks > 0);
    c->locks--;
#if CBDATA_DEBUG
    c->file = file;
    c->line = line;
#endif
    if (c->valid || c->locks)
	return;
    cbdataCount--;
    debug(45, 3) ("cbdataUnlock: Freeing %p\n", p);
    free_func = cbdata_index[c->type].free_func;
    if (free_func)
	free_func((void *) p);
    memPoolFree(cbdata_index[c->type].pool, c);
}

int
cbdataValid(const void *p)
{
    cbdata *c;
    if (p == NULL)
	return 1;		/* A NULL pointer cannot become invalid */
    debug(45, 3) ("cbdataValid: %p\n", p);
    c = (cbdata *) (((char *) p) - OFFSET_OF(cbdata, data));
    assert(c->y == c);
    assert(c->locks > 0);
    return c->valid;
}

static void
cbdataDump(StoreEntry * sentry)
{
    storeAppendPrintf(sentry, "%d cbdata entries\n", cbdataCount);
    storeAppendPrintf(sentry, "see also memory pools section\n");
}
