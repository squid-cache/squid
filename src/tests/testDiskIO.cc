#define SQUID_UNIT_TEST 1

#include "squid.h"
#include "testDiskIO.h"
#include "Store.h"
#include "SwapDir.h"
#include "DiskIO/DiskIOModule.h"
#include "fs/ufs/ufscommon.h"
#if 0 // AYJ: COSS in Squid-3 is disabled.
#include "fs/coss/CossSwapDir.h"
#endif
#include "Mem.h"
#include "MemObject.h"
#include "HttpHeader.h"
#include "HttpReply.h"
#include "StoreFileSystem.h"
#include "testStoreSupport.h"

#if HAVE_STDEXCEPT
#include <stdexcept>
#endif

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
