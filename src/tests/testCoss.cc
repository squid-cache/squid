#include "squid.h"
#include <stdexcept>

#include "testCoss.h"
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

#define TESTDIR "testCoss__testCossSearch"

CPPUNIT_TEST_SUITE_REGISTRATION( testCoss );

typedef RefCount<CossSwapDir> SwapDirPointer;
extern REMOVALPOLICYCREATE createRemovalPolicy_lru;

static void
addSwapDir(SwapDirPointer aStore)
{
    allocate_new_swapdir(&Config.cacheSwap);
    Config.cacheSwap.swapDirs[Config.cacheSwap.n_configured] = aStore.getRaw();
    ++Config.cacheSwap.n_configured;
}

void
testCoss::commonInit()
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
testCoss::testCossCreate()
{
    if (0 > system ("rm -rf " TESTDIR))
        throw std::runtime_error("Failed to clean test work directory");

    StorePointer aRoot (new StoreController);

    Store::Root(aRoot);

    SwapDirPointer aStore (new CossSwapDir());

    addSwapDir(aStore);

    commonInit();

    char *path=xstrdup(TESTDIR);

    char *config_line=xstrdup("foo 100 max-size=102400 block-size=512 IOEngine=Blocking");

    strtok(config_line, w_space);

    aStore->parse(0, path);

    safe_free(path);

    safe_free(config_line);

    /* ok, ready to create */
    aStore->create();

    struct stat sb;

    CPPUNIT_ASSERT(::stat(TESTDIR, &sb) == 0);

    /* TODO: check the size */

    free_cachedir(&Config.cacheSwap);

    Store::Root(NULL);

    /* todo: here we should test a dirty rebuild */

    //    safe_free(Config.replPolicy->type);
    //    delete Config.replPolicy;
    if (0 > system ("rm -rf " TESTDIR))
        throw std::runtime_error("Failed to clean test work directory");
}

/* TODO make this a cbdata class */

static bool cbcalled;

static void
searchCallback(void *cbdata)
{
    cbcalled = true;
}

void
testCoss::testCossSearch()
{
    /* test sequence
     * make a valid working ufs swapdir
     * put two entries in it and sync logs
     * search the ufs dir
     * check the entries we find are what we want
     */

    if (0 > system ("rm -rf " TESTDIR))
        throw std::runtime_error("Failed to clean test work directory");

    StorePointer aRoot (new StoreController);

    Store::Root(aRoot);

    SwapDirPointer aStore (new CossSwapDir());

    addSwapDir(aStore);

    commonInit();

    char *path=xstrdup(TESTDIR);

    char *config_line=xstrdup("foo 100 max-size=102400 block-size=512 IOEngine=Blocking");

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

    /* our swapdir must be scheduled to rebuild */
    CPPUNIT_ASSERT_EQUAL(1, StoreController::store_dirs_rebuilding);

    loop.run();

    /* cannot use loop.run(); as the loop will never idle: the store-dir
     * clean() scheduled event prevents it 
     */

    /* nothing left to rebuild */
    CPPUNIT_ASSERT_EQUAL(0, StoreController::store_dirs_rebuilding);

    /* add an entry */
    {
        /* Create "vary" base object */
        request_flags flags;
        flags.cachable = 1;
        StoreEntry *pe = storeCreateEntry("dummy url", "dummy log url", flags, METHOD_GET);
        HttpVersion version(1, 0);
        HttpReply *rep = (HttpReply *) pe->getReply();	// bypass const
        rep->setHeaders(version, HTTP_OK, "dummy test object", "x-squid-internal/test", -1, -1, squid_curtime + 100000);

        storeSetPublicKey(pe);

        storeBuffer(pe);
        /* TODO: remove this when the metadata is separated */
        {
            Packer p;
            packerToStoreInit(&p, pe);
            pe->getReply()->packHeadersInto(&p);
            packerClean(&p);
        }

        storeBufferFlush(pe);
        storeTimestampsSet(pe);
        pe->complete();
        storeSwapOut(pe);
        CPPUNIT_ASSERT(pe->swap_dirn == 0);
        CPPUNIT_ASSERT(pe->swap_filen == 0);
        pe->unlock();
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

    Store::Root(NULL);

    /* todo: here we should test a dirty rebuild */

    //TODO: do this once, or each time.    safe_free(Config.replPolicy->type);
    //    delete Config.replPolicy;

    if (0 > system ("rm -rf " TESTDIR))
        throw std::runtime_error("Failed to clean test work directory");
}

/* The COSS store should always configure an IO engine even if none is 
 * supplied on the configuration line.
 */
void
testCoss::testDefaultEngine()
{
    /* boring common test boilerplate */
    if (0 > system ("rm -rf " TESTDIR))
        throw std::runtime_error("Failed to clean test work directory");

    StorePointer aRoot (new StoreController);
    Store::Root(aRoot);
    SwapDirPointer aStore (new CossSwapDir());
    addSwapDir(aStore);
    commonInit();

    char *path=xstrdup(TESTDIR);
    char *config_line=xstrdup("foo 100 max-size=102400 block-size=512");
    strtok(config_line, w_space);
    aStore->parse(0, path);
    safe_free(path);
    safe_free(config_line);
    CPPUNIT_ASSERT(aStore->io != NULL);

    free_cachedir(&Config.cacheSwap);
    Store::Root(NULL);
    if (0 > system ("rm -rf " TESTDIR))
        throw std::runtime_error("Failed to clean test work directory");
}
