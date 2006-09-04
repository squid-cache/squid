
/*
 * $Id: cbdata.cc,v 1.75 2006/09/03 21:05:20 hno Exp $
 *
 * DEBUG: section 45    Callback Data Registry
 * ORIGINAL AUTHOR: Duane Wessels
 * Modified by Moez Mahfoudh (08/12/2000)
 * History added by Robert Collins (2002-10-25)
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

#include "cbdata.h"
#include "CacheManager.h"
#include "Store.h"
#if CBDATA_DEBUG
#include "Stack.h"
#endif
#include "Generic.h"

#if WITH_VALGRIND
#define HASHED_CBDATA 1
#endif

static int cbdataCount = 0;
#if CBDATA_DEBUG
dlink_list cbdataEntries;
#endif

#if CBDATA_DEBUG

class CBDataCall
{

public:
    CBDataCall (char const *callLabel, char const *aFile, int aLine) : label(callLabel), file(aFile), line(aLine){}

    char const *label;
    char const *file;
    int line;
};

#endif

#define OFFSET_OF(TYPE, MEMBER) ((size_t) &(((TYPE) *)0)->(MEMBER))

class cbdata
{
    /* TODO: examine making cbdata templated on this - so we get type
     * safe access to data - RBC 20030902 */
public:
#if HASHED_CBDATA
    hash_link hash;	// Must be first
#endif

#if CBDATA_DEBUG

    void dump(StoreEntry *)const;
#endif

#if !HASHED_CBDATA
    void *operator new(size_t size, void *where);
    void operator delete(void *where, void *where2);
#else
    MEMPROXY_CLASS(cndata);
#endif

    ~cbdata();
    int valid;
    int locks;
    cbdata_type type;
#if CBDATA_DEBUG

    void addHistory(char const *label, char const *file, int line)
    {
        if (calls.size() > 1000)
            return;

        calls.push_back(new CBDataCall(label, file, line));
    }

    dlink_node link;
    const char *file;
    int line;
    Stack<CBDataCall*> calls;
#endif

    /* cookie used while debugging */
    long cookie;
    void check(int line) const {assert(cookie == ((long)this ^ Cookie));}
    static const long Cookie;

#if !HASHED_CBDATA
    size_t dataSize() const { return sizeof(data);}
    static long MakeOffset();
    static const long Offset;
    /* MUST be the last per-instance member */
    void *data;
#endif

};

const long cbdata::Cookie((long)0xDEADBEEF);
#if !HASHED_CBDATA
const long cbdata::Offset(MakeOffset());

void *
cbdata::operator new(size_t size, void *where)
{
    // assert (size == sizeof(cbdata));
    return where;
}

void
cbdata::operator delete(void *where, void *where2)
{
    /* Only ever invoked when placement new throws
     * an exception. Used to prevent an incorrect
     * free.
     */
}

long
cbdata::MakeOffset()
{
    cbdata *zero = (cbdata *)0L;
    void **dataOffset = &zero->data;
    return (long)dataOffset;
}
#else
MEMPROXY_CLASS_INLINE(cbdata)
#endif

static OBJH cbdataDump;
#ifdef CBDATA_DEBUG
static OBJH cbdataDumpHistory;
#endif

struct CBDataIndex
{
    MemAllocator *pool;
    FREE *free_func;
}

*cbdata_index = NULL;
int cbdata_types = 0;

#if HASHED_CBDATA
static hash_table *cbdata_htable = NULL;

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
#endif


cbdata::~cbdata()
{
#if CBDATA_DEBUG
    CBDataCall *aCall;

    while ((aCall = calls.pop()))
        delete aCall;

#endif

    FREE *free_func = cbdata_index[type].free_func;

#if HASHED_CBDATA
    void *p = hash.key;
#else
    void *p = &data;
#endif

    if (free_func)
        free_func(p);
}

static void
cbdataInternalInitType(cbdata_type type, const char *name, int size, FREE * free_func)
{
    char *label;
    assert (type == cbdata_types + 1);

    cbdata_index = (CBDataIndex *)xrealloc(cbdata_index, (type + 1) * sizeof(*cbdata_index));
    memset(&cbdata_index[type], 0, sizeof(*cbdata_index));
    cbdata_types = type;

    label = (char *)xmalloc(strlen(name) + 20);

    snprintf(label, strlen(name) + 20, "cbdata %s (%d)", name, (int) type);

#if !HASHED_CBDATA
    assert((size_t)cbdata::Offset == (sizeof(cbdata) - ((cbdata *)NULL)->dataSize()));
    size += cbdata::Offset;
#endif

    cbdata_index[type].pool = memPoolCreate(label, size);

    cbdata_index[type].free_func = free_func;

#if HASHED_CBDATA
    if (!cbdata_htable)
	cbdata_htable = hash_create(cbdata_cmp, 1 << 12, cbdata_hash);
#endif
}

cbdata_type
cbdataInternalAddType(cbdata_type type, const char *name, int size, FREE * free_func)
{
    if (type)
        return type;

    type = (cbdata_type)(cbdata_types + 1);

    cbdataInternalInitType(type, name, size, free_func);

    return type;
}

void
cbdataRegisterWithCacheManager(CacheManager & manager)
{
    manager.registerAction("cbdata",
                           "Callback Data Registry Contents",
                           cbdataDump, 0, 1);
#if CBDATA_DEBUG

    manager.registerAction("cbdatahistory",
                           "Detailed call history for all current cbdata contents",
                           cbdataDumpHistory, 0, 1);
#endif
}

void *
#if CBDATA_DEBUG
cbdataInternalAllocDbg(cbdata_type type, const char *file, int line)
#else
cbdataInternalAlloc(cbdata_type type)
#endif
{
    cbdata *c;
    void *p;
    assert(type > 0 && type <= cbdata_types);
    /* placement new: the pool alloc gives us cbdata + user type memory space
     * and we init it with cbdata at the start of it
     */
#if HASHED_CBDATA
    c = new cbdata;
    p = cbdata_index[type].pool->alloc();
    c->hash.key = p;
    hash_join(cbdata_htable, &c->hash);
#else
    c = new (cbdata_index[type].pool->alloc()) cbdata;
    p = (void *)&c->data;
#endif

    c->type = type;
    c->valid = 1;
    c->locks = 0;
    c->cookie = (long) c ^ cbdata::Cookie;
    cbdataCount++;
#if CBDATA_DEBUG

    c->file = file;
    c->line = line;
    c->calls = Stack<CBDataCall *> ();
    c->addHistory("Alloc", file, line);
    dlinkAdd(c, &c->link, &cbdataEntries);
    debug(45, 3) ("cbdataAlloc: %p %s:%d\n", p, file, line);
#endif

    return p;
}

void *
#if CBDATA_DEBUG
cbdataInternalFreeDbg(void *p, const char *file, int line)
#else
cbdataInternalFree(void *p)
#endif
{
    cbdata *c;
#if HASHED_CBDATA
    c = (cbdata *) hash_lookup(cbdata_htable, p);
#else
    c = (cbdata *) (((char *) p) - cbdata::Offset);
#endif
#if CBDATA_DEBUG

    debug(45, 3) ("cbdataFree: %p %s:%d\n", p, file, line);
#else

    debug(45, 9) ("cbdataFree: %p\n", p);
#endif

    c->check(__LINE__);
    assert(c->valid);
    c->valid = 0;
#if CBDATA_DEBUG

    c->addHistory("Free", file, line);
#endif

    if (c->locks) {
        debug(45, 9) ("cbdataFree: %p has %d locks, not freeing\n",
                      p, c->locks);
        return NULL;
    }

    cbdataCount--;
    debug(45, 9) ("cbdataFree: Freeing %p\n", p);
#if CBDATA_DEBUG

    dlinkDelete(&c->link, &cbdataEntries);
#endif

    /* This is ugly. But: operator delete doesn't get
     * the type parameter, so we can't use that 
     * to free the memory.
     * So, we free it ourselves.
     * Note that this means a non-placement 
     * new would be a seriously bad idea.
     * Lastly, if we where a templated class,
     * we could use the normal delete operator
     * and it would Just Work. RBC 20030902
     */
    cbdata_type theType = c->type;
#if HASHED_CBDATA
    hash_remove_link(cbdata_htable, &c->hash);
    delete c;
    cbdata_index[theType].pool->free((void *)p);
#else
    c->cbdata::~cbdata();
    cbdata_index[theType].pool->free(c);
#endif
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

#if HASHED_CBDATA
    c = (cbdata *) hash_lookup(cbdata_htable, p);
#else
    c = (cbdata *) (((char *) p) - cbdata::Offset);
#endif

#if CBDATA_DEBUG

    debug(45, 3) ("cbdataLock: %p=%d %s:%d\n", p, c ? c->locks + 1 : -1, file, line);

    c->addHistory("Reference", file, line);

#else

    debug(45, 9) ("cbdataLock: %p=%d\n", p, c ? c->locks + 1 : -1);

#endif

    c->check(__LINE__);

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

    if (p == NULL)
        return;

#if HASHED_CBDATA
    c = (cbdata *) hash_lookup(cbdata_htable, p);
#else
    c = (cbdata *) (((char *) p) - cbdata::Offset);
#endif

#if CBDATA_DEBUG

    debug(45, 3) ("cbdataUnlock: %p=%d %s:%d\n", p, c ? c->locks - 1 : -1, file, line);

    c->addHistory("Dereference", file, line);

#else

    debug(45, 9) ("cbdataUnlock: %p=%d\n", p, c ? c->locks - 1 : -1);

#endif

    c->check(__LINE__);

    assert(c != NULL);

    assert(c->locks > 0);

    c->locks--;

    if (c->valid || c->locks)
        return;

    cbdataCount--;

    debug(45, 9) ("cbdataUnlock: Freeing %p\n", p);

#if CBDATA_DEBUG

    dlinkDelete(&c->link, &cbdataEntries);

#endif

    /* This is ugly. But: operator delete doesn't get
     * the type parameter, so we can't use that 
     * to free the memory.
     * So, we free it ourselves.
     * Note that this means a non-placement 
     * new would be a seriously bad idea.
     * Lastly, if we where a templated class,
     * we could use the normal delete operator
     * and it would Just Work. RBC 20030902
     */
    cbdata_type theType = c->type;
#if HASHED_CBDATA
    hash_remove_link(cbdata_htable, &c->hash);
    delete c;
    cbdata_index[theType].pool->free((void *)p);
#else
    c->cbdata::~cbdata();
    cbdata_index[theType].pool->free(c);
#endif
}

int
cbdataReferenceValid(const void *p)
{
    cbdata *c;

    if (p == NULL)
        return 1;		/* A NULL pointer cannot become invalid */

    debug(45, 9) ("cbdataReferenceValid: %p\n", p);

#if HASHED_CBDATA
    c = (cbdata *) hash_lookup(cbdata_htable, p);
#else
    c = (cbdata *) (((char *) p) - cbdata::Offset);
#endif

    c->check(__LINE__);

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

#if CBDATA_DEBUG
void
cbdata::dump(StoreEntry *sentry) const
{
#if HASHED_CBDATA
    void *p = (void *)hash.key;
#else
    void *p = (void *)&data;
#endif
    storeAppendPrintf(sentry, "%c%p\t%d\t%d\t%20s:%-5d\n", valid ? ' ' :
                      '!', p, type, locks, file, line);
}

struct CBDataDumper : public unary_function<cbdata, void>
{
    CBDataDumper(StoreEntry *anEntry):where(anEntry){}

    void operator()(cbdata const &x)
    {
        x.dump(where);
    }

    StoreEntry *where;
};

#endif

static void
cbdataDump(StoreEntry * sentry)
{
    storeAppendPrintf(sentry, "%d cbdata entries\n", cbdataCount);
#if CBDATA_DEBUG

    storeAppendPrintf(sentry, "Pointer\tType\tLocks\tAllocated by\n");
    CBDataDumper dumper(sentry);
    for_each (cbdataEntries, dumper);
    storeAppendPrintf(sentry, "\n");
    storeAppendPrintf(sentry, "types\tsize\tallocated\ttotal\n");

    for (int i = 1; i < cbdata_types; i++) {
        MemAllocator *pool = cbdata_index[i].pool;

        if (pool) {
#if HASHED_CBDATA
            int obj_size = pool->objectSize();
#else
            int obj_size = pool->objectSize() - cbdata::Offset;
#endif
            storeAppendPrintf(sentry, "%s\t%d\t%ld\t%ld\n", pool->objectType() + 7, obj_size, (long int)pool->getMeter().inuse.level, (long int)obj_size * pool->getMeter().inuse.level);
        }
    }

#else
    storeAppendPrintf(sentry, "detailed allocation information only available when compiled with CBDATA_DEBUG\n");

#endif

    storeAppendPrintf(sentry, "\nsee also \"Memory utilization\" for detailed per type statistics\n");
}

CBDATA_CLASS_INIT(generic_cbdata);

#if CBDATA_DEBUG

struct CBDataCallDumper : public unary_function<CBDataCall, void>
{
    CBDataCallDumper (StoreEntry *anEntry):where(anEntry){}

    void operator()(CBDataCall const &x)
    {
        storeAppendPrintf(where, "%s\t%s\t%d\n", x.label, x.file, x.line);
    }

    StoreEntry *where;
};

struct CBDataHistoryDumper : public CBDataDumper
{
    CBDataHistoryDumper(StoreEntry *anEntry):CBDataDumper(anEntry),where(anEntry), callDumper(anEntry){}

    void operator()(cbdata const &x)
    {
        CBDataDumper::operator()(x);
        storeAppendPrintf(where, "\n");
        storeAppendPrintf(where, "Action\tFile\tLine\n");
        for_each (x.calls,callDumper);
        storeAppendPrintf(where, "\n");
    }

    StoreEntry *where;
    CBDataCallDumper callDumper;
};

void
cbdataDumpHistory(StoreEntry *sentry)
{
    storeAppendPrintf(sentry, "%d cbdata entries\n", cbdataCount);
    storeAppendPrintf(sentry, "Pointer\tType\tLocks\tAllocated by\n");
    CBDataHistoryDumper dumper(sentry);
    for_each (cbdataEntries, dumper);
}

#endif
