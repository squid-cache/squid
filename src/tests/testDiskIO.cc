/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "compat/cppunit.h"
#include "DiskIO/DiskIOModule.h"
#include "HttpHeader.h"
#include "HttpReply.h"
#include "MemObject.h"
#include "Store.h"
#include "StoreFileSystem.h"
#include "testStoreSupport.h"
#include "unitTestMain.h"

#include <stdexcept>

/*
 * test the DiskIO framework
 */

class TestDiskIO : public CPPUNIT_NS::TestFixture
{
    CPPUNIT_TEST_SUITE(TestDiskIO);
    CPPUNIT_TEST(testFindDefault);
    CPPUNIT_TEST_SUITE_END();

public:
    void setUp() override;

protected:
    void testFindDefault();
};

CPPUNIT_TEST_SUITE_REGISTRATION( TestDiskIO );

void
TestDiskIO::setUp()
{
    Mem::Init();
    DiskIOModule::SetupAllModules();
}

void
TestDiskIO::testFindDefault()
{
    DiskIOModule * module = DiskIOModule::FindDefault();
#if USE_DISKIO
    /* enabled. we expect at least ONE */
    CPPUNIT_ASSERT(module != nullptr);
#else
    /* disabled. we don't expect ANY */
    CPPUNIT_ASSERT(module == NULL);
#endif
}

