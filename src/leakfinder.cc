
/*
 * $Id: leakfinder.cc,v 1.9 2003/02/21 22:50:09 robertc Exp $
 *
 * DEBUG: section 45    Callback Data Registry
 * AUTHOR: Duane Wessels
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
 * Use these to find memory leaks
 */

#include "squid.h"
#include "Store.h"

static hash_table *htable = NULL;

static int leakCount = 0;

typedef struct _ptr
{
    hash_link hash;		/* must be first */
    void *key;

    struct _ptr *next;
    const char *file;
    int line;
    time_t when;
}

ptr;

static HASHCMP ptr_cmp;
static HASHHASH ptr_hash;
static OBJH ptrDump;

/* ========================================================================= */

void
leakInit(void)
{
    debug(45, 3) ("ptrInit\n");
    htable = hash_create(ptr_cmp, 1 << 8, ptr_hash);
    cachemgrRegister("leaks",
                     "Memory Leak Tracking",
                     ptrDump, 0, 1);
}

void *
leakAddFL(void *p, const char *file, int line)
{
    ptr *c;
    assert(p);
    assert(htable != NULL);
    assert(hash_lookup(htable, p) == NULL);
    c = (ptr *)xcalloc(1, sizeof(*c));
    c->key = p;
    c->file = file;
    c->line = line;
    c->when = squid_curtime;
    hash_join(htable, &c->hash);
    leakCount++;
    return p;
}

void *
leakTouchFL(void *p, const char *file, int line)
{
    ptr *c = (ptr *) hash_lookup(htable, p);
    assert(p);
    assert(htable != NULL);
    assert(c);
    c->file = file;
    c->line = line;
    c->when = squid_curtime;
    return p;
}

void *
leakFreeFL(void *p, const char *file, int line)
{
    ptr *c = (ptr *) hash_lookup(htable, p);
    assert(p);
    assert(c != NULL);
    hash_remove_link(htable, (hash_link *) c);
    leakCount--;
    xfree(c);
    return p;
}

/* ========================================================================= */

static int
ptr_cmp(const void *p1, const void *p2)
{
    return (char *) p1 - (char *) p2;
}

static unsigned int
ptr_hash(const void *p, unsigned int mod)
{
    return ((unsigned long) p >> 8) % mod;
}


static void
ptrDump(StoreEntry * sentry)
{
    hash_link *hptr;
    ptr *c;
    storeAppendPrintf(sentry, "Tracking %d pointers\n", leakCount);
    hash_first(htable);

    while ((hptr = (hash_link *)hash_next(htable))) {
        c = (ptr *) hptr;
        storeAppendPrintf(sentry, "%20p last used %9d seconds ago by %s:%d\n",
                          c->key, (int)(squid_curtime - c->when), c->file, c->line);
    }
}
