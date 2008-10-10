
#ifndef SQUID_SRC_TEST_STORE_H
#define SQUID_SRC_TEST_STORE_H

#include "squid.h"
#include "Store.h"

#include <cppunit/extensions/HelperMacros.h>


/*
 * test the store framework
 */

class testStore : public CPPUNIT_NS::TestFixture
{
    CPPUNIT_TEST_SUITE( testStore );
    CPPUNIT_TEST( testSetRoot );
    CPPUNIT_TEST( testUnsetRoot );
    CPPUNIT_TEST( testStats );
    CPPUNIT_TEST( testMaxSize );
    CPPUNIT_TEST_SUITE_END();

public:

protected:
    void testSetRoot();
    void testUnsetRoot();
    void testStats();
    void testMaxSize();
};


/* subclass of Store to allow testing of methods without having all the
 * other components live
 */

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

    virtual void reference(StoreEntry &) {}	/* Reference this object */

    virtual void dereference(StoreEntry &) {}	/* Unreference this object */

    virtual void updateSize(int64_t size, int sign) {}

    virtual StoreSearch *search(String const url, HttpRequest *);
};

typedef RefCount<TestStore> TestStorePointer;


#endif

