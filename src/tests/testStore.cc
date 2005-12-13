#include "squid.h"
#include "testStore.h"
#include "Store.h"

CPPUNIT_TEST_SUITE_REGISTRATION( testStore );

class TestStore : public Store
{

public:
    TestStore() : statsCalled (false) {}

    bool statsCalled;

    virtual int callback();

    virtual StoreEntry* get
        (const cache_key*);

    virtual void get
        (String, void (*)(StoreEntry*, void*), void*);

    virtual void init();

virtual void maintain() {};

    virtual size_t maxSize() const;

    virtual size_t minSize() const;

    virtual void stat(StoreEntry &) const; /* output stats to the provided store entry */

    virtual void reference(StoreEntry &){}	/* Reference this object */

    virtual void dereference(StoreEntry &){}	/* Unreference this object */

    virtual void updateSize(size_t size, int sign) {}

    virtual StoreSearch *search(String const url, HttpRequest *);
};

typedef RefCount<TestStore> TestStorePointer;

int
TestStore::callback()
{
    return 1;
}

StoreEntry*

TestStore::get
    (const cache_key*)
{
    return NULL;
}

void

TestStore::get
    (String, void (*)(StoreEntry*, void*), void*)
{}

void

TestStore::init()
{}

size_t
TestStore::maxSize() const
{
    return 3;
}

size_t
TestStore::minSize() const
{
    return 1;
}

void
TestStore::stat(StoreEntry &) const
{
    const_cast<TestStore *>(this)->statsCalled = true;
}

StoreSearch *
TestStore::search(String const url, HttpRequest *)
{
    return NULL;
}

void
testStore::testSetRoot()
{
    StorePointer aStore (new TestStore);
    Store::Root(aStore);

    CPPUNIT_ASSERT(&Store::Root() == aStore.getRaw());
    Store::Root(NULL);
}

void
testStore::testUnsetRoot()
{
    StorePointer aStore (new TestStore);
    StorePointer aStore2 (new TestStore);
    Store::Root(aStore);
    Store::Root(aStore2);
    CPPUNIT_ASSERT(&Store::Root() == aStore2.getRaw());
    Store::Root(NULL);
}

void
testStore::testStats()
{
    TestStorePointer aStore (new TestStore);
    Store::Root(aStore.getRaw());
    CPPUNIT_ASSERT(aStore->statsCalled == false);
    Store::Stats(NullStoreEntry::getInstance());
    CPPUNIT_ASSERT(aStore->statsCalled == true);
    Store::Root(NULL);
}

void
testStore::testMaxSize()
{
    StorePointer aStore (new TestStore);
    Store::Root(aStore.getRaw());
    CPPUNIT_ASSERT(aStore->maxSize() == 3);
    Store::Root(NULL);
}
