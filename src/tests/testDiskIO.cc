/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "DiskIO/DiskIOModule.h"
#include "HttpHeader.h"
#include "HttpReply.h"
#include "Mem.h"
#include "MemObject.h"
#include "Store.h"
#include "StoreFileSystem.h"
#include "SwapDir.h"
#include "testDiskIO.h"
#include "testStoreSupport.h"
#include "unitTestMain.h"

#include <stdexcept>

CPPUNIT_TEST_SUITE_REGISTRATION( testDiskIO );

void
testDiskIO::setUp()
{
    Mem::Init();
    DiskIOModule::SetupAllModules();
}

void
testDiskIO::testFindDefault()
{
    DiskIOModule * module = DiskIOModule::FindDefault();
#if USE_DISKIO
    /* enabled. we expect at least ONE */
    CPPUNIT_ASSERT(module != NULL);
#else
    /* disabled. we don't expect ANY */
    CPPUNIT_ASSERT(module == NULL);
#endif
}

