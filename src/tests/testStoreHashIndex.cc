/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "MemObject.h"
#include "SquidConfig.h"
#include "SquidTime.h"
#include "Store.h"
#include "store/Disks.h"
#include "StoreSearch.h"
#include "testStoreHashIndex.h"
#include "TestSwapDir.h"

CPPUNIT_TEST_SUITE_REGISTRATION( testStoreHashIndex );

static void
addSwapDir(TestSwapDirPointer aStore)
{
    allocate_new_swapdir(&Config.cacheSwap);
    Config.cacheSwap.swapDirs[Config.cacheSwap.n_configured] = aStore.getRaw();
    ++Config.cacheSwap.n_configured;
}

void
testStoreHashIndex::testStats()
{
    StoreEntry *logEntry = new StoreEntry;
    logEntry->createMemObject("dummy_storeId", NULL, HttpRequestMethod());
    logEntry->store_status = STORE_PENDING;
    Store::Init();
    TestSwapDirPointer aStore (new TestSwapDir);
    TestSwapDirPointer aStore2 (new TestSwapDir);
    addSwapDir(aStore);
    addSwapDir(aStore2);
    CPPUNIT_ASSERT_EQUAL(false, aStore->statsCalled);
    CPPUNIT_ASSERT_EQUAL(false, aStore2->statsCalled);
    Store::Stats(logEntry);
    free_cachedir(&Config.cacheSwap);
    CPPUNIT_ASSERT_EQUAL(true, aStore->statsCalled);
    CPPUNIT_ASSERT_EQUAL(true, aStore2->statsCalled);
    Store::FreeMemory();
}

void
testStoreHashIndex::testMaxSize()
{
    StoreEntry *logEntry = new StoreEntry;
    logEntry->createMemObject("dummy_storeId", NULL, HttpRequestMethod());
    logEntry->store_status = STORE_PENDING;
    Store::Init();
    TestSwapDirPointer aStore (new TestSwapDir);
    TestSwapDirPointer aStore2 (new TestSwapDir);
    addSwapDir(aStore);
    addSwapDir(aStore2);
    CPPUNIT_ASSERT_EQUAL(static_cast<uint64_t>(6), Store::Root().maxSize());
    free_cachedir(&Config.cacheSwap);
    Store::FreeMemory();
}

StoreEntry *
addedEntry(Store::Disk *aStore,
           String name,
           String varySpec,
           String varyKey

          )
{
    StoreEntry *e = new StoreEntry();
    e->store_status = STORE_OK;
    e->setMemStatus(NOT_IN_MEMORY);
    e->swap_status = SWAPOUT_DONE; /* bogus haha */
    e->swap_filen = 0; /* garh - lower level*/
    e->swap_dirn = -1;

    for (int i=0; i < Config.cacheSwap.n_configured; ++i) {
        if (INDEXSD(i) == aStore)
            e->swap_dirn = i;
    }

    CPPUNIT_ASSERT (e->swap_dirn != -1);
    e->swap_file_sz = 0; /* garh lower level */
    e->lastref = squid_curtime;
    e->timestamp = squid_curtime;
    e->expires = squid_curtime;
    e->lastModified(squid_curtime);
    e->refcount = 1;
    e->ping_status = PING_NONE;
    EBIT_CLR(e->flags, ENTRY_VALIDATED);
    e->hashInsert((const cache_key *)name.termedBuf()); /* do it after we clear KEY_PRIVATE */
    return e;
}

void commonInit()
{
    static bool inited = false;

    if (inited)
        return;

    Mem::Init();

    Config.Store.avgObjectSize = 1024;

    Config.Store.objectsPerBucket = 20;

    Config.Store.maxObjectSize = 2048;
}

/* TODO make this a cbdata class */

static bool cbcalled;

static void
searchCallback(void *cbdata)
{
    cbcalled = true;
}

void
testStoreHashIndex::testSearch()
{
    commonInit();
    Store::Init();
    TestSwapDirPointer aStore (new TestSwapDir);
    TestSwapDirPointer aStore2 (new TestSwapDir);
    addSwapDir(aStore);
    addSwapDir(aStore2);
    Store::Root().init();
    StoreEntry * entry1 = addedEntry(aStore.getRaw(), "name", NULL, NULL);
    StoreEntry * entry2 = addedEntry(aStore2.getRaw(), "name2", NULL, NULL);
    StoreSearchPointer search = Store::Root().search(); /* search for everything in the store */

    /* nothing should be immediately available */
    CPPUNIT_ASSERT_EQUAL(false, search->error());
    CPPUNIT_ASSERT_EQUAL(false, search->isDone());
    CPPUNIT_ASSERT_EQUAL(static_cast<StoreEntry *>(NULL), search->currentItem());
#if 0

    CPPUNIT_ASSERT_EQUAL(false, search->next());
#endif

    /* trigger a callback */
    cbcalled = false;
    search->next(searchCallback, NULL);
    CPPUNIT_ASSERT_EQUAL(true, cbcalled);

    /* we should have access to a entry now, that matches the entry we had before */
    CPPUNIT_ASSERT_EQUAL(false, search->error());
    CPPUNIT_ASSERT_EQUAL(false, search->isDone());
    /* note the hash order is random - the test happens to be in a nice order */
    CPPUNIT_ASSERT_EQUAL(entry1, search->currentItem());
    //CPPUNIT_ASSERT_EQUAL(false, search->next());

    /* trigger another callback */
    cbcalled = false;
    search->next(searchCallback, NULL);
    CPPUNIT_ASSERT_EQUAL(true, cbcalled);

    /* we should have access to a entry now, that matches the entry we had before */
    CPPUNIT_ASSERT_EQUAL(false, search->error());
    CPPUNIT_ASSERT_EQUAL(false, search->isDone());
    CPPUNIT_ASSERT_EQUAL(entry2, search->currentItem());
    //CPPUNIT_ASSERT_EQUAL(false, search->next());

    /* trigger another callback */
    cbcalled = false;
    search->next(searchCallback, NULL);
    CPPUNIT_ASSERT_EQUAL(true, cbcalled);

    /* now we should have no error, we should have finished and have no current item */
    CPPUNIT_ASSERT_EQUAL(false, search->error());
    CPPUNIT_ASSERT_EQUAL(true, search->isDone());
    CPPUNIT_ASSERT_EQUAL(static_cast<StoreEntry *>(NULL), search->currentItem());
    //CPPUNIT_ASSERT_EQUAL(false, search->next());

    Store::FreeMemory();
}

