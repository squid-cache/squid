/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 45    Callback Data Registry */

#include "squid.h"
#include "cbdata.h"
#include "Generic.h"
#include "mem/Allocator.h"
#include "mem/Pool.h"
#include "mgr/Registration.h"
#include "Store.h"

#include <climits>
#include <cstddef>

#if WITH_VALGRIND
#include <map>
#endif

static int cbdataCount = 0;

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

    /* TODO: examine making cbdata templated on this - so we get type
     * safe access to data - RBC 20030902 */
public:
    cbdata() :
        valid(0),
        locks(0),
        type(CBDATA_UNKNOWN),
        cookie(0),
        data(nullptr)
    {}
    ~cbdata();

    static cbdata *FromUserData(const void *);

    int valid;
    int32_t locks;
    cbdata_type type;

    /* cookie used while debugging */
    long cookie;
    void check(int) const {assert(cookie == ((long)this ^ Cookie));}
    static const long Cookie;

#if !WITH_VALGRIND
    size_t dataSize() const { return sizeof(data);}
#endif
    /* MUST be the last per-instance member */
    void *data;
};

static_assert(std::is_standard_layout<cbdata>::value, "the behavior of offsetof(cbdata) is defined");

const long cbdata::Cookie((long)0xDEADBEEF);

struct CBDataIndex {
    Mem::Allocator *pool;
}
*cbdata_index = nullptr;

int cbdata_types = 0;

#if WITH_VALGRIND
static std::map<const void *, cbdata *> cbdata_htable;
#endif

cbdata::~cbdata()
{
#if WITH_VALGRIND
    void *p = data;
#else
    void *p = this;
#endif
    cbdata_index[type].pool->freeOne(p);
}

cbdata *
cbdata::FromUserData(const void *p) {
#if WITH_VALGRIND
    return cbdata_htable.at(p);
#else
    const auto t = static_cast<const char *>(p) - offsetof(cbdata, data);
    return reinterpret_cast<cbdata *>(const_cast<char *>(t));
#endif
}

cbdata_type
cbdataInternalAddType(cbdata_type type, const char *name, int size)
{
    if (type)
        return type;

    type = (cbdata_type)(cbdata_types + 1);

    char *label;
    assert (type == cbdata_types + 1);

    cbdata_index = (CBDataIndex *)xrealloc(cbdata_index, (type + 1) * sizeof(*cbdata_index));
    memset(&cbdata_index[type], 0, sizeof(*cbdata_index));
    cbdata_types = type;

    label = (char *)xmalloc(strlen(name) + 20);

    snprintf(label, strlen(name) + 20, "cbdata %s (%d)", name, (int) type);

#if !WITH_VALGRIND
    size += offsetof(cbdata, data);
#endif

    cbdata_index[type].pool = memPoolCreate(label, size);

    return type;
}

void *
cbdataInternalAlloc(cbdata_type type)
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
    debugs(45, 9, "Allocating " << p);
    return p;
}

static void
cbdataRealFree(cbdata *c)
{
#if WITH_VALGRIND
    void *p = c->data;
#else
    void *p = (void *)&c->data;
#endif

    --cbdataCount;
    debugs(45, 9, "Freeing " << p);

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
cbdataInternalFree(void *p)
{
    auto *c = cbdata::FromUserData(p);

    c->check(__LINE__);
    assert(c->valid);
    c->valid = 0;

    if (c->locks) {
        debugs(45, 9, p << " has " << c->locks << " locks, not freeing");
        return nullptr;
    }

    cbdataRealFree(c);
    return nullptr;
}

void
cbdataInternalLock(const void *p)
{
    if (p == nullptr)
        return;

    auto *c = cbdata::FromUserData(p);

    debugs(45, 9, p << "=" << (c ? c->locks + 1 : -1));

    c->check(__LINE__);

    assert(c->locks < INT_MAX);

    ++ c->locks;
}

void
cbdataInternalUnlock(const void *p)
{
    if (p == nullptr)
        return;

    auto *c = cbdata::FromUserData(p);

    debugs(45, 9, p << "=" << (c ? c->locks - 1 : -1));

    c->check(__LINE__);

    assert(c != nullptr);

    assert(c->locks > 0);

    -- c->locks;

    if (c->locks)
        return;

    if (c->valid)
        return;

    cbdataRealFree(c);
}

int
cbdataReferenceValid(const void *p)
{
    if (p == nullptr)
        return 1;       /* A NULL pointer cannot become invalid */

    debugs(45, 9, p);

    const auto c = cbdata::FromUserData(p);

    c->check(__LINE__);

    assert(c->locks > 0);

    return c->valid;
}

int
cbdataInternalReferenceDoneValid(void **pp, void **tp)
{
    void *p = (void *) *pp;
    int valid = cbdataReferenceValid(p);
    *pp = nullptr;

    cbdataInternalUnlock(p);

    if (valid) {
        *tp = p;
        return 1;
    } else {
        *tp = nullptr;
        return 0;
    }
}

CallbackData &
CallbackData::operator =(const CallbackData &other)
{
    if (data_ != other.data_) { // assignment to self and no-op assignments
        auto old = data_;
        data_ = cbdataReference(other.data_);
        cbdataReferenceDone(old);
    }
    return *this;
}

CBDATA_CLASS_INIT(generic_cbdata);

