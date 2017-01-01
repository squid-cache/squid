/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_TEST_STORE_H
#define SQUID_SRC_TEST_STORE_H

#include "Store.h"
#include "store/Controlled.h"

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

/// allows testing of methods without having all the other components live
class TestStore : public Store::Controller
{

public:
    TestStore() : statsCalled (false) {}

    bool statsCalled;

    virtual int callback();

    virtual StoreEntry* get(const cache_key*);

    virtual void get(String, void (*)(StoreEntry*, void*), void*);

    virtual void init();

    virtual void maintain() {};

    virtual uint64_t maxSize() const;

    virtual uint64_t minSize() const;

    virtual uint64_t currentSize() const;

    virtual uint64_t currentCount() const;

    virtual int64_t maxObjectSize() const;

    virtual void getStats(StoreInfoStats &) const;

    virtual void stat(StoreEntry &) const; /* output stats to the provided store entry */

    virtual void reference(StoreEntry &) {} /* Reference this object */

    virtual bool dereference(StoreEntry &) { return true; }

    virtual StoreSearch *search();
};

typedef RefCount<TestStore> TestStorePointer;

#endif

