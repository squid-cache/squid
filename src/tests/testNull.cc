#include "squid.h"
#include <stdexcept>

#include "testNull.h"
#include "Store.h"
#include "SwapDir.h"
#include "DiskIO/DiskIOModule.h"
#include "fs/ufs/ufscommon.h"
#include "fs/null/store_null.h"
#include "Mem.h"
#include "MemObject.h"
#include "HttpHeader.h"
#include "HttpReply.h"
#include "StoreFileSystem.h"
#include "testStoreSupport.h"

#define TESTDIR "testNull__testNullSearch"

CPPUNIT_TEST_SUITE_REGISTRATION( testNull );

typedef RefCount<NullSwapDir> SwapDirPointer;
extern REMOVALPOLICYCREATE createRemovalPolicy_lru;

static void
addSwapDir(SwapDirPointer aStore)
{
    allocate_new_swapdir(&Config.cacheSwap);
    Config.cacheSwap.swapDirs[Config.cacheSwap.n_configured] = aStore.getRaw();
    ++Config.cacheSwap.n_configured;
}

void
testNull::commonInit()
{
    static bool inited = false;

    if (inited)
        return;

    StoreFileSystem::SetupAllFs();

    Config.Store.avgObjectSize = 1024;

    Config.Store.objectsPerBucket = 20;

    Config.Store.maxObjectSize = 2048;

    Config.store_dir_select_algorithm = xstrdup("round-robin");

    Config.replPolicy = new RemovalPolicySettings;

    Config.replPolicy->type = xstrdup ("lru");

    Config.replPolicy->args = NULL;

    /* garh garh */
    storeReplAdd("lru", createRemovalPolicy_lru);

    visible_appname_string = xstrdup(PACKAGE "/" VERSION);

    Mem::Init();

    comm_init();

    httpHeaderInitModule();	/* must go before any header processing (e.g. the one in errorInitialize) */

    httpReplyInitModule();	/* must go before accepting replies */

    mem_policy = createRemovalPolicy(Config.replPolicy);

    inited = true;
}

void
testNull::testNullCreate()
{
    StorePointer aRoot (new StoreController);
    Store::Root(aRoot);
    SwapDirPointer aStore (new NullSwapDir());
    addSwapDir(aStore);

    commonInit();

    char *path=xstrdup(TESTDIR);
    char *config_line=xstrdup("foo");
    strtok(config_line, w_space);
    aStore->parse(0, path);
    safe_free(path);
    safe_free(config_line);

    /* ok, ready to create */
    aStore->create();

    free_cachedir(&Config.cacheSwap);
    Store::Root(NULL);

    /* todo: here we should test a dirty rebuild */

    //    safe_free(Config.replPolicy->type);
    //    delete Config.replPolicy;
}

/* TODO make this a cbdata class */

static bool cbcalled;

static void
searchCallback(void *cbdata)
{
    cbcalled = true;
}

void
testNull::testNullSearch()
{
    /* test sequence
     * make a valid working ufs swapdir
     * put two entries in it and sync logs
     * search the ufs dir
     * check the entries we find are what we want
     */
    StorePointer aRoot (new StoreController);
    Store::Root(aRoot);
    SwapDirPointer aStore (new NullSwapDir());
    addSwapDir(aStore);

    commonInit();

    char *path=xstrdup(TESTDIR);
    char *config_line=xstrdup("foo");
    strtok(config_line, w_space);
    aStore->parse(0, path);
    safe_free(path);
    safe_free(config_line);

    /* ok, ready to create */
    aStore->create();

    /* ok, ready to use */
    Store::Root().init();

    /* rebuild is a scheduled event */
    StockEventLoop loop;

    /* our swapdir must be scheduled to rebuild - though it does not
     * make sense to rebuild Null stores at all.  store_dirs_rebuilding
     * is initialized to _1_ and adding our swapdir makes it 2.
     */
    CPPUNIT_ASSERT_EQUAL(2, StoreController::store_dirs_rebuilding);

    loop.run();

    /* nothing left to rebuild */
    CPPUNIT_ASSERT_EQUAL(1, StoreController::store_dirs_rebuilding);

    /* add an entry */
    {
        /* Create "vary" base object */
        request_flags flags;
        flags.cachable = 1;
        StoreEntry *pe = storeCreateEntry("dummy url", "dummy log url", flags, METHOD_GET);
        HttpVersion version(1, 0);
        /* We are allowed to do this typecast */
        HttpReply *rep = (HttpReply *) pe->getReply();	// bypass const
        rep->setHeaders(version, HTTP_OK, "dummy test object", "x-squid-internal/test", -1, -1, squid_curtime + 100000);

        pe->setPublicKey();

        pe->buffer();
        /* TODO: remove this when the metadata is separated */
        {
            Packer p;
            packerToStoreInit(&p, pe);
            pe->getReply()->packHeadersInto(&p);
            packerClean(&p);
        }

        pe->flush();
        pe->timestampsSet();
        pe->complete();
        pe->swapOut();
        /* Null does not accept store entries */
        CPPUNIT_ASSERT(pe->swap_dirn == -1);
        pe->unlock();
    }

    storeDirWriteCleanLogs(0);

    /* here we cheat: we know that UFSSwapDirs search off disk. If we did an init call to a new
     * swapdir instance, we'd not be testing a clean build.
     */
    StoreSearchPointer search = aStore->search (NULL, NULL); /* search for everything in the store */

    /* nothing should be available */
    CPPUNIT_ASSERT(search->error() == false);
    CPPUNIT_ASSERT(search->isDone() == true);
    CPPUNIT_ASSERT(search->currentItem() == NULL);
    CPPUNIT_ASSERT(search->next() == false);

    /* trigger a callback */
    cbcalled = false;
    search->next(searchCallback, NULL);
    CPPUNIT_ASSERT(cbcalled == true);

    /* still nothing */
    CPPUNIT_ASSERT(search->error() == false);
    CPPUNIT_ASSERT(search->isDone() == true);
    CPPUNIT_ASSERT(search->currentItem() == NULL);
    CPPUNIT_ASSERT(search->next() == false);

    free_cachedir(&Config.cacheSwap);
    Store::Root(NULL);

    //TODO: do this once, or each time.    safe_free(Config.replPolicy->type);
    //    delete Config.replPolicy;
}
