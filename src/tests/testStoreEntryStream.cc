/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "CapturingStoreEntry.h"
#include "Mem.h"
#include "Store.h"
#include "StoreEntryStream.h"
#include "testStore.h"
#include "testStoreEntryStream.h"

#include <iomanip>
#include <cppunit/TestAssert.h>

CPPUNIT_TEST_SUITE_REGISTRATION( testStoreEntryStream );

/* init memory pools */

void testStoreEntryStream::setUp()
{
    Mem::Init();
}

void
testStoreEntryStream::testGetStream()
{
    /* Setup a store root so we can create a StoreEntry */
    StorePointer aStore (new TestStore);
    Store::Root(aStore);

    CapturingStoreEntry * anEntry = new CapturingStoreEntry();
    {
        StoreEntryStream stream(anEntry); // locks and unlocks/deletes anEntry
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

        CPPUNIT_ASSERT_EQUAL(String("12345677.7 some text   !."),
                             anEntry->_appended_text);
    }
    Store::Root(NULL);
}

