
/*
 * $Id: cbdata.cc,v 1.34 2001/01/07 23:36:37 hno Exp $
 *
 * DEBUG: section 45    Callback Data Registry
 * ORIGINAL AUTHOR: Duane Wessels
 * Modified by Moez Mahfoudh (08/12/2000)
 *
 * SQUID Internet Object Cache  http://squid.nlanr.net/Squid/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from the
 *  Internet community.  Development is led by Duane Wessels of the
 *  National Laboratory for Applied Network Research and funded by the
 *  National Science Foundation.  Squid is Copyrighted (C) 1998 by
 *  the Regents of the University of California.  Please see the
 *  COPYRIGHT file for full details.  Squid incorporates software
 *  developed and/or copyrighted by other sources.  Please see the
 *  CREDITS file for full details.
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
    CBDUNL *unlock_func;
    int type;			/* move to CBDATA_DEBUG with type argument to cbdataFree */
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

static MemPool **cbdata_memory_pool = NULL;
int cbdata_types = 0;

#define OFFSET_OF(type, member) ((int)(char *)&((type *)0L)->member)

void
cbdataInitType(cbdata_type type, char *name, int size)
{
    char *label;
    if (type >= cbdata_types) {
	cbdata_memory_pool = xrealloc(cbdata_memory_pool, (type + 1) * sizeof(*cbdata_memory_pool));
	memset(&cbdata_memory_pool[cbdata_types], 0,
	    (type + 1 - cbdata_types) * sizeof(*cbdata_memory_pool));
	cbdata_types = type + 1;
    }
    if (cbdata_memory_pool[type])
	return;
    label = xmalloc(strlen(name) + 20);
    snprintf(label, strlen(name) + 20, "cbdata %s (%d)", name, (int) type);
    assert(OFFSET_OF(cbdata, data) == (sizeof(cbdata) - sizeof(((cbdata *) NULL)->data)));
    cbdata_memory_pool[type] = memPoolCreate(label, size + OFFSET_OF(cbdata, data));
}

cbdata_type
cbdataAddType(cbdata_type type, char *name, int size)
{
    if (type)
	return type;
    type = cbdata_types;
    cbdataInitType(type, name, size);
    return type;
}

void
cbdataInit(void)
{
    debug(45, 3) ("cbdataInit\n");
    cachemgrRegister("cbdata",
	"Callback Data Registry Contents",
	cbdataDump, 0, 1);
#define CREATE_CBDATA(type) cbdataInitType(CBDATA_##type, #type, sizeof(type))
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
    CREATE_CBDATA(peer);
    CREATE_CBDATA(ps_state);
    CREATE_CBDATA(RemovalPolicy);
    CREATE_CBDATA(RemovalPolicyWalker);
    CREATE_CBDATA(RemovalPurgeWalker);
    CREATE_CBDATA(store_client);
    CREATE_CBDATA(storeIOState);
}

void *
#if CBDATA_DEBUG
cbdataInternalAllocDbg(cbdata_type type, CBDUNL * unlock_func, const char *file, int line)
#else
cbdataInternalAlloc(cbdata_type type, CBDUNL * unlock_func)
#endif
{
    cbdata *p;
    assert(type > 0 && type < cbdata_types);
    p = memPoolAlloc(cbdata_memory_pool[type]);
    p->type = type;
    p->unlock_func = unlock_func;
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

void
cbdataFree(void *p)
{
    cbdata *c;
    debug(45, 3) ("cbdataFree: %p\n", p);
    assert(p);
    c = (cbdata *) (((char *) p) - OFFSET_OF(cbdata, data));
    assert(c->y == c);
    c->valid = 0;
    if (c->locks) {
	debug(45, 3) ("cbdataFree: %p has %d locks, not freeing\n",
	    p, c->locks);
	return;
    }
    cbdataCount--;
    debug(45, 3) ("cbdataFree: Freeing %p\n", p);
    if (c->unlock_func)
	c->unlock_func((void *) p);
    memPoolFree(cbdata_memory_pool[c->type], c);
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
    if (c->unlock_func)
	c->unlock_func((void *) p);
    memPoolFree(cbdata_memory_pool[c->type], c);
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
