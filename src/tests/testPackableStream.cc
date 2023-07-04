/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "base/PackableStream.h"
#include "CapturingStoreEntry.h"
#include "compat/cppunit.h"
#include "Store.h"
#include "testStore.h"

#include <iomanip>
#include <cppunit/TestAssert.h>

class TestPackableStream : public CPPUNIT_NS::TestFixture
{
    CPPUNIT_TEST_SUITE(TestPackableStream);
    CPPUNIT_TEST(testGetStream);
    CPPUNIT_TEST_SUITE_END();

public:
    void setUp() override;

protected:
    void testGetStream();
};

CPPUNIT_TEST_SUITE_REGISTRATION( TestPackableStream );

/* init memory pools */

void TestPackableStream::setUp()
{
    Mem::Init();
}

// TODO: test streaming to a MemBuf as well.

void
TestPackableStream::testGetStream()
{
    /* Setup a store root so we can create a StoreEntry */
    Store::Init();

    CapturingStoreEntry * anEntry = new CapturingStoreEntry();
    {
        anEntry->lock("test");
        PackableStream stream(*anEntry);
        CPPUNIT_ASSERT_EQUAL(1, anEntry->_buffer_calls);
        CPPUNIT_ASSERT_EQUAL(0, anEntry->_flush_calls);

        stream.setf(std::ios::fixed);
        stream << 123456 << std::setprecision(1) << 77.7;
        stream << " some text" << std::setw(4) << "!" << '.';
        CPPUNIT_ASSERT_EQUAL(1, anEntry->_buffer_calls);

        const int preFlushCount = anEntry->_flush_calls;
        // may have already flushed
        CPPUNIT_ASSERT(preFlushCount >= 0);
        stream.flush();
        // flushed at least once more
        CPPUNIT_ASSERT(anEntry->_flush_calls > preFlushCount);

        CPPUNIT_ASSERT_EQUAL(1, anEntry->_buffer_calls);
        CPPUNIT_ASSERT_EQUAL(String("12345677.7 some text   !."), anEntry->_appended_text);
    }
    delete anEntry; // does the unlock()
    Store::FreeMemory();
}

