#define SQUID_UNIT_TEST 1

#include "squid.h"

#include "testStoreHashIndex.h"
#include "Store.h"
#include "SwapDir.h"
#include "TestSwapDir.h"
#include "StoreHashIndex.h"
#include "Mem.h"
#include "StoreSearch.h"
#include "SquidTime.h"

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
    StoreEntry * logEntry = new StoreEntry("dummy_url", "dummy_log_url");
    logEntry->store_status = STORE_PENDING;
    StorePointer aRoot (new StoreHashIndex());
    Store::Root(aRoot);
    TestSwapDirPointer aStore (new TestSwapDir);
    TestSwapDirPointer aStore2 (new TestSwapDir);
    addSwapDir(aStore);
    addSwapDir(aStore2);
    CPPUNIT_ASSERT(aStore->statsCalled == false);
    CPPUNIT_ASSERT(aStore2->statsCalled == false);
    Store::Stats(logEntry);
    free_cachedir(&Config.cacheSwap);
    CPPUNIT_ASSERT(aStore->statsCalled == true);
    CPPUNIT_ASSERT(aStore2->statsCalled == true);
    Store::Root(NULL);
}

void
testStoreHashIndex::testMaxSize()
{
    StoreEntry * logEntry = new StoreEntry("dummy_url", "dummy_log_url");
    logEntry->store_status = STORE_PENDING;
    StorePointer aRoot (new StoreHashIndex());
    Store::Root(aRoot);
    TestSwapDirPointer aStore (new TestSwapDir);
    TestSwapDirPointer aStore2 (new TestSwapDir);
    addSwapDir(aStore);
    addSwapDir(aStore2);
    CPPUNIT_ASSERT(Store::Root().maxSize() == 6);
    free_cachedir(&Config.cacheSwap);
    Store::Root(NULL);
}

StoreEntry *
addedEntry(StorePointer hashStore,
           StorePointer aStore,
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

    for (int i=0; i < Config.cacheSwap.n_configured; i++) {
        if (INDEXSD (i) == aStore.getRaw())
            e->swap_dirn = i;
    }

    CPPUNIT_ASSERT (e->swap_dirn != -1);
    e->swap_file_sz = 0; /* garh lower level */
    e->lock_count = 0;
    e->lastref = squid_curtime;
    e->timestamp = squid_curtime;
    e->expires = squid_curtime;
    e->lastmod = squid_curtime;
    e->refcount = 1;
    EBIT_SET(e->flags, ENTRY_CACHABLE);
    EBIT_CLR(e->flags, RELEASE_REQUEST);
    EBIT_CLR(e->flags, KEY_PRIVATE);
    e->ping_status = PING_NONE;
    EBIT_CLR(e->flags, ENTRY_VALIDATED);
    e->hashInsert((const cache_key *)name.termedBuf());	/* do it after we clear KEY_PRIVATE */
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
    StorePointer aRoot (new StoreHashIndex());
    Store::Root(aRoot);
    TestSwapDirPointer aStore (new TestSwapDir);
    TestSwapDirPointer aStore2 (new TestSwapDir);
    addSwapDir(aStore);
    addSwapDir(aStore2);
    Store::Root().init();
    StoreEntry * entry1 = addedEntry (&Store::Root(), aStore.getRaw(), "name", NULL, NULL);
    StoreEntry * entry2 = addedEntry (&Store::Root(), aStore2.getRaw(), "name2", NULL, NULL);
    StoreSearchPointer search = aRoot->search (NULL, NULL); /* search for everything in the store */

    /* nothing should be immediately available */
    CPPUNIT_ASSERT(search->error() == false);
    CPPUNIT_ASSERT(search->isDone() == false);
    CPPUNIT_ASSERT(search->currentItem() == NULL);
#if 0

    CPPUNIT_ASSERT(search->next() == false);
#endif

    /* trigger a callback */
    cbcalled = false;
    search->next(searchCallback, NULL);
    CPPUNIT_ASSERT(cbcalled == true);

    /* we should have access to a entry now, that matches the entry we had before */
    CPPUNIT_ASSERT(search->error() == false);
    CPPUNIT_ASSERT(search->isDone() == false);
    /* note the hash order is random - the test happens to be in a nice order */
    CPPUNIT_ASSERT(search->currentItem() == entry1);
    //CPPUNIT_ASSERT(search->next() == false);

    /* trigger another callback */
    cbcalled = false;
    search->next(searchCallback, NULL);
    CPPUNIT_ASSERT(cbcalled == true);

    /* we should have access to a entry now, that matches the entry we had before */
    CPPUNIT_ASSERT(search->error() == false);
    CPPUNIT_ASSERT(search->isDone() == false);
    CPPUNIT_ASSERT(search->currentItem() == entry2);
    //CPPUNIT_ASSERT(search->next() == false);

    /* trigger another callback */
    cbcalled = false;
    search->next(searchCallback, NULL);
    CPPUNIT_ASSERT(cbcalled == true);

    /* now we should have no error, we should have finished and have no current item */
    CPPUNIT_ASSERT(search->error() == false);
    CPPUNIT_ASSERT(search->isDone() == true);
    CPPUNIT_ASSERT(search->currentItem() == NULL);
    //CPPUNIT_ASSERT(search->next() == false);

    Store::Root(NULL);
}
