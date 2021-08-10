/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_TEST_TESTSBUF_H
#define SQUID_SRC_TEST_TESTSBUF_H

#include "compat/cppunit.h"

#include "base/TextException.h"

/*
 * test the SBuf functionalities
 */

class testSBuf : public CPPUNIT_NS::TestFixture
{
    CPPUNIT_TEST_SUITE( testSBuf );
    CPPUNIT_TEST( testSBufConstructDestruct );
    CPPUNIT_TEST( testSBufConstructDestructAfterMemInit );
    CPPUNIT_TEST( testSBufLength );
    CPPUNIT_TEST( testEqualityTest );
    CPPUNIT_TEST( testStartsWith );
    CPPUNIT_TEST( testAppendSBuf );
    CPPUNIT_TEST( testAppendCString );
    CPPUNIT_TEST( testAppendStdString );
    CPPUNIT_TEST( testAppendf );
    CPPUNIT_TEST( testSubscriptOp );
    CPPUNIT_TEST_EXCEPTION( testSubscriptOpFail, TextException );
    CPPUNIT_TEST( testComparisons );
    CPPUNIT_TEST( testConsume );
    CPPUNIT_TEST( testRawContent );
    CPPUNIT_TEST( testRawSpace );
    CPPUNIT_TEST( testChop );
    CPPUNIT_TEST( testChomp );
    CPPUNIT_TEST( testSubstr );
    CPPUNIT_TEST( testFindChar );
    CPPUNIT_TEST( testFindSBuf );
    CPPUNIT_TEST( testRFindChar );
    CPPUNIT_TEST( testRFindSBuf );
    CPPUNIT_TEST( testFindFirstOf );
    CPPUNIT_TEST( testFindFirstNotOf );
    CPPUNIT_TEST( testPrintf );
    CPPUNIT_TEST( testCopy );
    CPPUNIT_TEST( testStringOps );
    CPPUNIT_TEST( testGrow );
    CPPUNIT_TEST( testReserve );
    CPPUNIT_TEST( testSBufStream );
    CPPUNIT_TEST( testAutoFind );
    CPPUNIT_TEST( testStdStringOps );
    CPPUNIT_TEST( testIterators );
    CPPUNIT_TEST( testSBufHash );
//    CPPUNIT_TEST( testDumpStats ); //fake test, to print alloc stats
    CPPUNIT_TEST_SUITE_END();
protected:
    void commonInit();
    void testSBufConstructDestruct();
    void testSBufConstructDestructAfterMemInit();
    void testEqualityTest();
    void testAppendSBuf();
    void testAppendCString();
    void testAppendStdString();
    void testAppendf();
    void testPrintf();
    void testSubscriptOp();
    void testSubscriptOpFail();
    void testDumpStats();
    void testComparisons();
    void testConsume();
    void testRawContent();
    void testRawSpace();
    void testChop();
    void testChomp();
    void testSubstr();
    void testTailCopy();
    void testSBufLength();
    void testFindChar();
    void testFindSBuf();
    void testRFindChar();
    void testRFindSBuf();
    void testSearchFail();
    void testCopy();
    void testStringOps();
    void testGrow();
    void testReserve();
    void testStartsWith();
    void testSBufStream();
    void testFindFirstOf();
    void testFindFirstNotOf();
    void testAutoFind();
    void testStdStringOps();
    void testIterators();
    void testSBufHash();
};

#endif

