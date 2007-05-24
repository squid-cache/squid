#include "squid.h"
#include <stdexcept>

#include "testDiskIO.h"
#include "Store.h"
#include "SwapDir.h"
#include "DiskIO/DiskIOModule.h"
#include "fs/ufs/ufscommon.h"
#include "fs/coss/CossSwapDir.h"
#include "Mem.h"
#include "MemObject.h"
#include "HttpHeader.h"
#include "HttpReply.h"
#include "StoreFileSystem.h"
#include "testStoreSupport.h"

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
    CPPUNIT_ASSERT(module != NULL);
}
