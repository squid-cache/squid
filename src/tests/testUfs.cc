#include "config.h"
#include <stdexcept>

#include "testUfs.h"
#include "squid.h"
#include "Store.h"
#include "SwapDir.h"
#include "DiskIO/DiskIOModule.h"
#include "fs/ufs/ufscommon.h"
#include "Mem.h"
#include "HttpHeader.h"
#include "HttpReply.h"

CPPUNIT_TEST_SUITE_REGISTRATION( testUfs );

typedef RefCount<UFSSwapDir> SwapDirPointer;
extern REMOVALPOLICYCREATE createRemovalPolicy_lru;

static void
addSwapDir(SwapDirPointer aStore)
{
    allocate_new_swapdir(&Config.cacheSwap);
    Config.cacheSwap.swapDirs[Config.cacheSwap.n_configured] = aStore.getRaw();
    ++Config.cacheSwap.n_configured;
}

/* TODO make this a cbdata class */

static bool cbcalled;

static void
searchCallback(void *cbdata)
{
    cbcalled = true;
}

void
testUfs::testUfsSearch()
{
    /* test sequence
     * make a valid working ufs swapdir
     * put two entries in it and sync logs
     * search the ufs dir
     * check the entries we find are what we want
     */

    if (0 > system ("rm -rf testUfs::testUfsSearch"))
        throw std::runtime_error("Failed to clean test work directory");

    StorePointer aRoot (new StoreController);

    Store::Root(aRoot);

    SwapDirPointer aStore (new UFSSwapDir("ufs", "Blocking"));

    aStore->IO = new UFSStrategy(DiskIOModule::Find("Blocking")->createStrategy());

    addSwapDir(aStore);

    Config.Store.avgObjectSize = 1024;

    Config.Store.objectsPerBucket = 20;

    Config.Store.maxObjectSize = 2048;

    Config.store_dir_select_algorithm = xstrdup("round-robin");

    Config.replPolicy = new RemovalPolicySettings;

    Config.replPolicy->type = xstrdup ("lru");

    /* garh garh */
    storeReplAdd("lru", createRemovalPolicy_lru);

    Mem::Init();

    cbdataInit();

    eventInit();		/* eventInit() is required for config parsing */

    comm_init();

    httpHeaderInitModule();	/* must go before any header processing (e.g. the one in errorInitialize) */

    httpReplyInitModule();	/* must go before accepting replies */

    mem_policy = createRemovalPolicy(Config.replPolicy);

    char *path=xstrdup("testUfs::testUfsSearch");

    char *config_line=xstrdup("foo 100 1 1");

    strtok(config_line, w_space);

    aStore->parse(0, path);

    safe_free(path);

    safe_free(config_line);

    /* ok, ready to create */
    aStore->create();

    /* ok, ready to use - init store & hash too */
    Store::Root().init();

    /* ensure rebuilding finishes */
    while (store_dirs_rebuilding > 1) {
        getCurrentTime();
        eventRun();
    }

    /* nothing to rebuild */
    CPPUNIT_ASSERT(store_dirs_rebuilding == 1);

    --store_dirs_rebuilding;

    /* add an entry */
    {
        /* Create "vary" base object */
        request_flags flags;
        flags.cachable = 1;
        StoreEntry *pe = storeCreateEntry("dummy url", "dummy log url", flags, METHOD_GET);
        HttpVersion version(1, 0);
        /* We are allowed to do this typecast */
        httpReplySetHeaders((HttpReply *)pe->getReply(), version, HTTP_OK, "dummy test object", "x-squid-internal/test", -1, -1, squid_curtime + 100000);

        storeSetPublicKey(pe);

        storeBuffer(pe);
        /* TODO: remove this when the metadata is separated */
        {
            Packer p;
            packerToStoreInit(&p, pe);
            httpReplyPackHeadersInto(pe->getReply(), &p);
            packerClean(&p);
        }

        storeBufferFlush(pe);
        storeTimestampsSet(pe);
        pe->complete();
        storeSwapOut(pe);
        CPPUNIT_ASSERT(pe->swap_dirn == 0);
        CPPUNIT_ASSERT(pe->swap_filen == 0);
        storeUnlockObject(pe);
    }

    storeDirWriteCleanLogs(0);

    /* here we cheat: we know that UFSSwapDirs search off disk. If we did an init call to a new
     * swapdir instance, we'd not be testing a clean build.
     */
    StoreSearchPointer search = aStore->search (NULL, NULL); /* search for everything in the store */

    /* nothing should be immediately available */
#if 0

    CPPUNIT_ASSERT(search->next() == false);
#endif

    CPPUNIT_ASSERT(search->error() == false);
    CPPUNIT_ASSERT(search->isDone() == false);
    CPPUNIT_ASSERT(search->currentItem() == NULL);

    /* trigger a callback */
    cbcalled = false;
    search->next(searchCallback, NULL);
    CPPUNIT_ASSERT(cbcalled == true);

    /* we should have access to a entry now, that matches the entry we had before */
    //CPPUNIT_ASSERT(search->next() == false);
    CPPUNIT_ASSERT(search->error() == false);
    CPPUNIT_ASSERT(search->isDone() == false);
    CPPUNIT_ASSERT(search->currentItem() != NULL);

    /* trigger another callback */
    cbcalled = false;
    search->next(searchCallback, NULL);
    CPPUNIT_ASSERT(cbcalled == true);

    /* now we should have no error, we should have finished and have no current item */
    //CPPUNIT_ASSERT(search->next() == false);
    CPPUNIT_ASSERT(search->error() == false);
    CPPUNIT_ASSERT(search->isDone() == true);
    CPPUNIT_ASSERT(search->currentItem() == NULL);

    free_cachedir(&Config.cacheSwap);

    /* todo: here we should test a dirty rebuild */

    safe_free(Config.replPolicy->type);
    delete Config.replPolicy;

    if (0 > system ("rm -rf testUfs::testUfsSearch"))
        throw std::runtime_error("Failed to clean test work directory");
}
