/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "sbuf/Algorithms.h"
#include "sbuf/List.h"
#include "tests/testSBufList.h"
#include "unitTestMain.h"

CPPUNIT_TEST_SUITE_REGISTRATION( testSBufList );

SBuf literal("The quick brown fox jumped over the lazy dog");
static int sbuf_tokens_number=9;
static SBuf tokens[]= {
    SBuf("The",3), SBuf("quick",5), SBuf("brown",5), SBuf("fox",3),
    SBuf("jumped",6), SBuf("over",4), SBuf("the",3), SBuf("lazy",4),
    SBuf("dog",3)
};

void
testSBufList::testSBufListMembership()
{
    SBufList foo;
    for (int j=0; j<sbuf_tokens_number; ++j)
        foo.push_back(tokens[j]);
    CPPUNIT_ASSERT_EQUAL(true,IsMember(foo,SBuf("fox")));
    CPPUNIT_ASSERT_EQUAL(true,IsMember(foo,SBuf("Fox"),caseInsensitive));
    CPPUNIT_ASSERT_EQUAL(false,IsMember(foo,SBuf("garble")));
}

void
testSBufList::testSBufListJoin()
{
    SBufList foo;
    CPPUNIT_ASSERT_EQUAL(SBuf(""),SBufContainerJoin(foo,SBuf()));
    CPPUNIT_ASSERT_EQUAL(SBuf(""),SBufContainerJoin(foo,SBuf()));
    for (int j = 0; j < sbuf_tokens_number; ++j)
        foo.push_back(tokens[j]);
    SBuf joined=SBufContainerJoin(foo,SBuf(" "));
    CPPUNIT_ASSERT_EQUAL(literal,joined);
}

