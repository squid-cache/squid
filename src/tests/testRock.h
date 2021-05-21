/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_TEST_TESTROCK_H
#define SQUID_SRC_TEST_TESTROCK_H

#include "compat/cppunit.h"

/*
 * test the store framework
 */

class testRock : public CPPUNIT_NS::TestFixture
{
    CPPUNIT_TEST_SUITE( testRock );
    CPPUNIT_TEST( testRockCreate );
    CPPUNIT_TEST( testRockSwapOut );
    CPPUNIT_TEST_SUITE_END();

public:
    testRock() : rr(NULL) {}
    virtual void setUp();
    virtual void tearDown();

    typedef RefCount<Rock::SwapDir> SwapDirPointer;

protected:
    void commonInit();
    void storeInit();
    StoreEntry *createEntry(const int i);
    StoreEntry *addEntry(const int i);
    StoreEntry *getEntry(const int i);
    void testRockCreate();
    void testRockSwapOut();

private:
    SwapDirPointer store;
    Rock::SwapDirRr *rr;
};

#endif /* SQUID_SRC_TEST_TESTROCK_H */

