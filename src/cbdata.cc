
/*
 * $Id: cbdata.cc,v 1.9 1997/11/28 08:01:03 wessels Exp $
 *
 * DEBUG: section 45    Callback Data Registry
 * AUTHOR: Duane Wessels
 *
 * SQUID Internet Object Cache  http://squid.nlanr.net/Squid/
 * --------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from the
 *  Internet community.  Development is led by Duane Wessels of the
 *  National Laboratory for Applied Network Research and funded by
 *  the National Science Foundation.
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
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
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
 * foo = xcalloc(sizeof(foo));
 * cbdataAdd(foo);
 * ...
 * cbdataLock(foo);
 * some_blocking_operation(..., callback_func, foo);
 * ...
 * some_blocking_operation_completes()
 * if (cbdataValid(foo))
 * callback_func(..., foo)
 * cbdataUnlock(foo);
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

static hash_table *htable = NULL;

static int cbdataCount = 0;

typedef struct _cbdata {
    void *key;
    struct _cbdata *next;
    int valid;
    int locks;
} cbdata;

static HASHCMP cbdata_cmp;
static HASHHASH cbdata_hash;

static int
cbdata_cmp(const void *p1, const void *p2)
{
    return (char *) p1 - (char *) p2;
}

static unsigned int
cbdata_hash(const void *p, unsigned int mod)
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
    cbdataCount++;
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
    cbdataCount--;
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
    cbdataCount--;
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
    storeAppendPrintf(sentry, "%d cbdata entries\n", cbdataCount);
    for (hptr = hash_first(htable); hptr; hptr = hash_next(htable)) {
	c = (cbdata *) hptr;
	storeAppendPrintf(sentry, "%20p %10s %d locks\n",
	    c->key,
	    c->valid ? "VALID" : "NOT VALID",
	    c->locks);
    }
}
