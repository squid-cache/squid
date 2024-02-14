/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_TESTS_TESTHTTP1PARSER_H
#define SQUID_SRC_TESTS_TESTHTTP1PARSER_H

#include "compat/cppunit.h"

class testHttp1Parser : public CPPUNIT_NS::TestFixture
{
    CPPUNIT_TEST_SUITE( testHttp1Parser );
    // object basics are working, just in case.
    CPPUNIT_TEST( testParserConstruct );
    CPPUNIT_TEST( testDripFeed );
    CPPUNIT_TEST( testParseRequestLineMethods );
    CPPUNIT_TEST( testParseRequestLineProtocols );
    CPPUNIT_TEST( testParseRequestLineTerminators );
    CPPUNIT_TEST( testParseRequestLineStrange );
    CPPUNIT_TEST( testParseRequestLineInvalid );
    CPPUNIT_TEST_SUITE_END();

protected:
    void globalSetup(); // MemPools init etc.

    void testParserConstruct(); // whether the constructor works

    // request-line unit tests
    void testParseRequestLineTerminators(); // terminator detection correct
    void testParseRequestLineMethods();     // methoid detection correct
    void testParseRequestLineProtocols();   // protocol tokens handled correctly
    void testParseRequestLineStrange();     // strange but valid lines accepted
    void testParseRequestLineInvalid();     // rejection of invalid lines happens

    void testDripFeed(); // test incremental parse works
};

#endif /* SQUID_SRC_TESTS_TESTHTTP1PARSER_H */

