/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 45    Callback Data Registry */

#include "squid.h"
#include "cbdata.h"
#include "Generic.h"
#include "mem/Pool.h"
#include "mgr/Registration.h"
#include "Store.h"

#include <climits>

#if USE_CBDATA_DEBUG
#include <algorithm>
#include <vector>
#endif

#if WITH_VALGRIND
#include <map>
#endif

static int cbdataCount = 0;
#if USE_CBDATA_DEBUG
dlink_list cbdataEntries;
#endif

#if USE_CBDATA_DEBUG

class CBDataCall
{

public:
    CBDataCall (char const *callLabel, char const *aFile, int aLine) : label(callLabel), file(aFile), line(aLine) {}

    char const *label;
    char const *file;
    int line;
};

#endif

#define OFFSET_OF(TYPE, MEMBER) ((size_t) &(((TYPE) *)0)->(MEMBER))

/**
 * Manage a set of registered callback data pointers.
 * One of the easiest ways to make Squid coredump is to issue a
 * callback to for some data structure which has previously been
 * freed.  With this class, we register (add) callback data
 * pointers, lock them just before registering the callback function,
 * validate them before issuing the callback, and then free them
 * when finished.
 */
class cbdata
{
#if !WITH_VALGRIND
public:
    void *operator new(size_t, void *where) {return where;}
    /**
     * Only ever invoked when placement new throws
     * an exception. Used to prevent an incorrect free.
     */
    void operator delete(void *, void *) {}
#else
    MEMPROXY_CLASS(cbdata);
#endif

    /** \todo examine making cbdata templated on this - so we get type
     * safe access to data - RBC 20030902 */
public:
#if USE_CBDATA_DEBUG

    void dump(StoreEntry *)const;
#endif
    cbdata() :
        valid(0),
        locks(0),
        type(CBDATA_UNKNOWN),
#if USE_CBDATA_DEBUG
        file(NULL),
        line(0),
#endif
        cookie(0),
        data(NULL)
    {}
    ~cbdata();

    int valid;
    int32_t locks;
    cbdata_type type;
#if USE_CBDATA_DEBUG

    void addHistory(char const *label, char const *aFile, int aLine) {
        if (calls.size() > 1000)
            return;

        calls.push_back(new CBDataCall(label, aFile, aLine));
    }

    dlink_node link;
    const char *file;
    int line;
    std::vector<CBDataCall*> calls; // used as a stack with random access operator
#endif

    /* cookie used while debugging */
    long cookie;
    void check(int) const {assert(cookie == ((long)this ^ Cookie));}
    static const long Cookie;

#if !WITH_VALGRIND
    size_t dataSize() const { return sizeof(data);}
    static long MakeOffset();
    static const long Offset;
#endif
    /* MUST be the last per-instance member */
    void *data;
};

const long cbdata::Cookie((long)0xDEADBEEF);
#if !WITH_VALGRIND
const long cbdata::Offset(MakeOffset());

long
cbdata::MakeOffset()
{
    cbdata *zero = (cbdata *)0L;
    void **dataOffset = &zero->data;
    return (long)dataOffset;
}
#endif

static OBJH cbdataDump;
#if USE_CBDATA_DEBUG
static OBJH cbdataDumpHistory;
#endif

struct CBDataIndex {
    MemAllocator *pool;
}
*cbdata_index = NULL;

int cbdata_types = 0;

#if WITH_VALGRIND
static std::map<const void *, cbdata *> cbdata_htable;
#endif

cbdata::~cbdata()
{
#if USE_CBDATA_DEBUG

    while (!calls.empty()) {
        delete calls.back();
        calls.pop_back();
    }

#endif

#if WITH_VALGRIND
    void *p = data;
#else
    void *p = this;
#endif
    cbdata_index[type].pool->freeOne(p);
}

static void
cbdataInternalInitType(cbdata_type type, const char *name, int size)
{
    char *label;
    assert (type == cbdata_types + 1);

    cbdata_index = (CBDataIndex *)xrealloc(cbdata_index, (type + 1) * sizeof(*cbdata_index));
    memset(&cbdata_index[type], 0, sizeof(*cbdata_index));
    cbdata_types = type;

    label = (char *)xmalloc(strlen(name) + 20);

    snprintf(label, strlen(name) + 20, "cbdata %s (%d)", name, (int) type);

#if !WITH_VALGRIND
    assert((size_t)cbdata::Offset == (sizeof(cbdata) - ((cbdata *)NULL)->dataSize()));
    size += cbdata::Offset;
#endif

    cbdata_index[type].pool = memPoolCreate(label, size);
}

cbdata_type
cbdataInternalAddType(cbdata_type type, const char *name, int size)
{
    if (type)
        return type;

    type = (cbdata_type)(cbdata_types + 1);

    cbdataInternalInitType(type, name, size);

    return type;
}

void
cbdataRegisterWithCacheManager(void)
{
    Mgr::RegisterAction("cbdata",
                        "Callback Data Registry Contents",
                        cbdataDump, 0, 1);
#if USE_CBDATA_DEBUG

    Mgr::RegisterAction("cbdatahistory",
                        "Detailed call history for all current cbdata contents",
                        cbdataDumpHistory, 0, 1);
#endif
}

void *
cbdataInternalAlloc(cbdata_type type, const char *file, int line)
{
    cbdata *c;
    void *p;
    assert(type > 0 && type <= cbdata_types);
    /* placement new: the pool alloc gives us cbdata + user type memory space
     * and we init it with cbdata at the start of it
     */
#if WITH_VALGRIND
    c = new cbdata;
    p = cbdata_index[type].pool->alloc();
    c->data = p;
    cbdata_htable.emplace(p,c);
#else
    c = new (cbdata_index[type].pool->alloc()) cbdata;
    p = (void *)&c->data;
#endif

    c->type = type;
    c->valid = 1;
    c->locks = 0;
    c->cookie = (long) c ^ cbdata::Cookie;
    ++cbdataCount;
#if USE_CBDATA_DEBUG

    c->file = file;
    c->line = line;
    c->calls = std::vector<CBDataCall *> ();
    c->addHistory("Alloc", file, line);
    dlinkAdd(c, &c->link, &cbdataEntries);
    debugs(45, 3, "Allocating " << p << " " << file << ":" << line);
#else
    debugs(45, 9, "Allocating " << p);
#endif

    return p;
}

void
cbdataRealFree(cbdata *c, const char *file, const int line)
{
#if WITH_VALGRIND
    void *p = c->data;
#else
    void *p = (void *)&c->data;
#endif

    --cbdataCount;
#if USE_CBDATA_DEBUG
    debugs(45, 3, "Freeing " << p << ' ' << file << ':' << line);
    dlinkDelete(&c->link, &cbdataEntries);
#else
    debugs(45, 9, "Freeing " << p);
#endif

#if WITH_VALGRIND
    cbdata_htable.erase(p);
    delete c;
#else
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
    c->cbdata::~cbdata();
#endif
}

void *
cbdataInternalFree(void *p, const char *file, int line)
{
    cbdata *c;
#if WITH_VALGRIND
    c = cbdata_htable.at(p);
#else
    c = (cbdata *) (((char *) p) - cbdata::Offset);
#endif
#if USE_CBDATA_DEBUG
    debugs(45, 3, p << " " << file << ":" << line);
#else
    debugs(45, 9, p);
#endif

    c->check(__LINE__);
    assert(c->valid);
    c->valid = 0;
#if USE_CBDATA_DEBUG

    c->addHistory("Free", file, line);
#endif

    if (c->locks) {
        debugs(45, 9, p << " has " << c->locks << " locks, not freeing");
        return NULL;
    }

    cbdataRealFree(c, file, line);
    return NULL;
}

void
#if USE_CBDATA_DEBUG
cbdataInternalLockDbg(const void *p, const char *file, int line)
#else
cbdataInternalLock(const void *p)
#endif
{
    cbdata *c;

    if (p == NULL)
        return;

#if WITH_VALGRIND
    c = cbdata_htable.at(p);
#else
    c = (cbdata *) (((char *) p) - cbdata::Offset);
#endif

#if USE_CBDATA_DEBUG
    debugs(45, 3, p << "=" << (c ? c->locks + 1 : -1) << " " << file << ":" << line);
    c->addHistory("Reference", file, line);
#else
    debugs(45, 9, p << "=" << (c ? c->locks + 1 : -1));
#endif

    c->check(__LINE__);

    assert(c->locks < INT_MAX);

    ++ c->locks;
}

void
#if USE_CBDATA_DEBUG
cbdataInternalUnlockDbg(const void *p, const char *file, int line)
#else
cbdataInternalUnlock(const void *p)
#endif
{
    cbdata *c;

    if (p == NULL)
        return;

#if WITH_VALGRIND
    c = cbdata_htable.at(p);
#else
    c = (cbdata *) (((char *) p) - cbdata::Offset);
#endif

#if USE_CBDATA_DEBUG
    debugs(45, 3, p << "=" << (c ? c->locks - 1 : -1) << " " << file << ":" << line);
    c->addHistory("Dereference", file, line);
#else
    debugs(45, 9, p << "=" << (c ? c->locks - 1 : -1));
#endif

    c->check(__LINE__);

    assert(c != NULL);

    assert(c->locks > 0);

    -- c->locks;

    if (c->locks)
        return;

    if (c->valid) {
#if USE_CBDATA_DEBUG
        debugs(45, 3, "CBDATA valid with no references ... cbdata=" << p << " " << file << ":" << line);
#endif
        return;
    }

#if USE_CBDATA_DEBUG
    cbdataRealFree(c, file, line);
#else
    cbdataRealFree(c, NULL, 0);
#endif
}

int
cbdataReferenceValid(const void *p)
{
    cbdata *c;

    if (p == NULL)
        return 1;       /* A NULL pointer cannot become invalid */

    debugs(45, 9, p);

#if WITH_VALGRIND
    c = cbdata_htable.at(p);
#else
    c = (cbdata *) (((char *) p) - cbdata::Offset);
#endif

    c->check(__LINE__);

    assert(c->locks > 0);

    return c->valid;
}

int
#if USE_CBDATA_DEBUG
cbdataInternalReferenceDoneValidDbg(void **pp, void **tp, const char *file, int line)
#else
cbdataInternalReferenceDoneValid(void **pp, void **tp)
#endif
{
    void *p = (void *) *pp;
    int valid = cbdataReferenceValid(p);
    *pp = NULL;
#if USE_CBDATA_DEBUG

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

#if USE_CBDATA_DEBUG
void
cbdata::dump(StoreEntry *sentry) const
{
#if WITH_VALGRIND
    void *p = data;
#else
    void *p = (void *)&data;
#endif
    storeAppendPrintf(sentry, "%c%p\t%d\t%d\t%20s:%-5d\n", valid ? ' ' :
                      '!', p, type, locks, file, line);
}

struct CBDataDumper : public unary_function<cbdata, void> {
    CBDataDumper(StoreEntry *anEntry):where(anEntry) {}

    void operator()(cbdata const &x) {
        x.dump(where);
    }

    StoreEntry *where;
};

#endif

static void
cbdataDump(StoreEntry * sentry)
{
    storeAppendPrintf(sentry, "%d cbdata entries\n", cbdataCount);
#if USE_CBDATA_DEBUG

    storeAppendPrintf(sentry, "Pointer\tType\tLocks\tAllocated by\n");
    CBDataDumper dumper(sentry);
    for_each (cbdataEntries, dumper);
    storeAppendPrintf(sentry, "\n");
    storeAppendPrintf(sentry, "types\tsize\tallocated\ttotal\n");

    for (int i = 1; i < cbdata_types; ++i) {
        MemAllocator *pool = cbdata_index[i].pool;

        if (pool) {
#if WITH_VALGRIND
            int obj_size = pool->objectSize();
#else
            int obj_size = pool->objectSize() - cbdata::Offset;
#endif
            storeAppendPrintf(sentry, "%s\t%d\t%ld\t%ld\n", pool->objectType() + 7, obj_size, (long int)pool->getMeter().inuse.currentLevel(), (long int)obj_size * pool->getMeter().inuse.currentLevel());
        }
    }

#else
    storeAppendPrintf(sentry, "detailed allocation information only available when compiled with --enable-debug-cbdata\n");

#endif

    storeAppendPrintf(sentry, "\nsee also \"Memory utilization\" for detailed per type statistics\n");
}

CBDATA_CLASS_INIT(generic_cbdata);

#if USE_CBDATA_DEBUG

struct CBDataCallDumper : public unary_function<CBDataCall, void> {
    CBDataCallDumper (StoreEntry *anEntry):where(anEntry) {}

    void operator()(CBDataCall * const &x) {
        storeAppendPrintf(where, "%s\t%s\t%d\n", x->label, x->file, x->line);
    }

    StoreEntry *where;
};

struct CBDataHistoryDumper : public CBDataDumper {
    CBDataHistoryDumper(StoreEntry *anEntry):CBDataDumper(anEntry),where(anEntry), callDumper(anEntry) {}

    void operator()(cbdata const &x) {
        CBDataDumper::operator()(x);
        storeAppendPrintf(where, "\n");
        storeAppendPrintf(where, "Action\tFile\tLine\n");
        std::for_each (x.calls.begin(), x.calls.end(), callDumper);
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

