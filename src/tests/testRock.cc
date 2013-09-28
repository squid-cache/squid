#define SQUID_UNIT_TEST 1
#include "squid.h"

#include "DiskIO/DiskIOModule.h"
#include "fs/rock/RockSwapDir.h"
#include "globals.h"
#include "HttpHeader.h"
#include "HttpReply.h"
#include "Mem.h"
#include "MemObject.h"
#include "RequestFlags.h"
#include "SquidConfig.h"
#include "Store.h"
#include "StoreFileSystem.h"
#include "StoreSearch.h"
#include "SwapDir.h"
#include "testRock.h"
#include "testStoreSupport.h"

#if HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif
#if HAVE_STDEXCEPT
#include <stdexcept>
#endif
#if HAVE_UNISTD_H
#include <unistd.h>
#endif

#define TESTDIR "testRock_Store"

CPPUNIT_TEST_SUITE_REGISTRATION( testRock );

extern REMOVALPOLICYCREATE createRemovalPolicy_lru;

static char cwd[MAXPATHLEN];

static void
addSwapDir(testRock::SwapDirPointer aStore)
{
    allocate_new_swapdir(&Config.cacheSwap);
    Config.cacheSwap.swapDirs[Config.cacheSwap.n_configured] = aStore.getRaw();
    ++Config.cacheSwap.n_configured;
}

void
testRock::setUp()
{
    CPPUNIT_NS::TestFixture::setUp();

    if (0 > system ("rm -rf " TESTDIR))
        throw std::runtime_error("Failed to clean test work directory");

    // use current directory for shared segments (on path-based OSes)
    Ipc::Mem::Segment::BasePath = getcwd(cwd,MAXPATHLEN);
    if (Ipc::Mem::Segment::BasePath == NULL)
        Ipc::Mem::Segment::BasePath = ".";

    Store::Root(new StoreController);

    store = new Rock::SwapDir();

    addSwapDir(store);

    commonInit();

    char *path=xstrdup(TESTDIR);

    char *config_line=xstrdup("foo 10 max-size=16384");

    strtok(config_line, w_space);

    store->parse(0, path);
    store_maxobjsize = 1024*1024*2;

    safe_free(path);

    safe_free(config_line);

    /* ok, ready to create */
    store->create();

    rr = new Rock::SwapDirRr;
    rr->run(rrAfterConfig);
}

void
testRock::tearDown()
{
    CPPUNIT_NS::TestFixture::tearDown();

    Store::Root(NULL);

    store = NULL;

    free_cachedir(&Config.cacheSwap);

    delete rr;

    // TODO: do this once, or each time.
    // safe_free(Config.replPolicy->type);
    // delete Config.replPolicy;

    if (0 > system ("rm -rf " TESTDIR))
        throw std::runtime_error("Failed to clean test work directory");
}

void
testRock::commonInit()
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

    visible_appname_string = xstrdup(APP_FULLNAME);

    Mem::Init();

    comm_init();

    httpHeaderInitModule();	/* must go before any header processing (e.g. the one in errorInitialize) */

    httpReplyInitModule();	/* must go before accepting replies */

    mem_policy = createRemovalPolicy(Config.replPolicy);

    inited = true;
}

void
testRock::storeInit()
{
    /* ok, ready to use */
    Store::Root().init();

    /* rebuild is a scheduled event */
    StockEventLoop loop;

    /* our swapdir must be scheduled to rebuild */
    CPPUNIT_ASSERT_EQUAL(2, StoreController::store_dirs_rebuilding);

    loop.run();

    /* cannot use loop.run(); as the loop will never idle: the store-dir
     * clean() scheduled event prevents it
     */

    /* nothing left to rebuild */
    CPPUNIT_ASSERT_EQUAL(1, StoreController::store_dirs_rebuilding);
}

StoreEntry *
testRock::createEntry(const int i)
{
    RequestFlags flags;
    flags.cachable = true;
    char url[64];
    snprintf(url, sizeof(url), "dummy url %i", i);
    url[sizeof(url) - 1] = '\0';
    StoreEntry *const pe =
        storeCreateEntry(url, "dummy log url", flags, Http::METHOD_GET);
    HttpReply *const rep = const_cast<HttpReply *>(pe->getReply());
    rep->setHeaders(Http::scOkay, "dummy test object", "x-squid-internal/test", 0, -1, squid_curtime + 100000);

    pe->setPublicKey();

    return pe;
}

StoreEntry *
testRock::addEntry(const int i)
{
    StoreEntry *const pe = createEntry(i);

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

    return pe;
}

StoreEntry *
testRock::getEntry(const int i)
{
    StoreEntry *const pe = createEntry(i);
    return store->get(reinterpret_cast<const cache_key *>(pe->key));
}

void
testRock::testRockCreate()
{
    struct stat sb;

    CPPUNIT_ASSERT(::stat(TESTDIR, &sb) == 0);

    /* TODO: check the size */

    /* TODO: test rebuild */
}

void
testRock::testRockSwapOut()
{
    storeInit();

    // add few entries to prime the database
    for (int i = 0; i < 5; ++i) {
        CPPUNIT_ASSERT_EQUAL((uint64_t)i, store->currentCount());

        StoreEntry *const pe = addEntry(i);

        CPPUNIT_ASSERT(pe->swap_status == SWAPOUT_WRITING);
        CPPUNIT_ASSERT(pe->swap_dirn == 0);
        CPPUNIT_ASSERT(pe->swap_filen >= 0);

        // Rock::IoState::finishedWriting() schedules an AsyncCall
        // storeSwapOutFileClosed().  Let it fire.
        StockEventLoop loop;
        loop.run();

        CPPUNIT_ASSERT(pe->swap_status == SWAPOUT_DONE);

        pe->unlock();
    }

    CPPUNIT_ASSERT_EQUAL((uint64_t)5, store->currentCount());

    // try to swap out entry to a used unlocked slot
    {
        StoreEntry *const pe = addEntry(4);

        CPPUNIT_ASSERT(pe->swap_status == SWAPOUT_WRITING);
        CPPUNIT_ASSERT(pe->swap_dirn == 0);
        CPPUNIT_ASSERT(pe->swap_filen >= 0);

        StockEventLoop loop;
        loop.run();

        CPPUNIT_ASSERT(pe->swap_status == SWAPOUT_DONE);
    }

    // try to swap out entry to a used locked slot
    {
        StoreEntry *const pe = addEntry(5);

        CPPUNIT_ASSERT(pe->swap_status == SWAPOUT_WRITING);
        CPPUNIT_ASSERT(pe->swap_dirn == 0);
        CPPUNIT_ASSERT(pe->swap_filen >= 0);

        // the slot is locked here because the async calls have not run yet
        StoreEntry *const pe2 = addEntry(5);
        CPPUNIT_ASSERT(pe2->swap_status == SWAPOUT_NONE);
        CPPUNIT_ASSERT(pe2->mem_obj->swapout.decision ==
                       MemObject::SwapOut::swImpossible);
        CPPUNIT_ASSERT(pe2->swap_dirn == -1);
        CPPUNIT_ASSERT(pe2->swap_filen == -1);

        StockEventLoop loop;
        loop.run();
    }

    CPPUNIT_ASSERT_EQUAL((uint64_t)6, store->currentCount());

    // try to get and unlink entries
    for (int i = 0; i < 6; ++i) {
        StoreEntry *const pe = getEntry(i);
        CPPUNIT_ASSERT(pe != NULL);

        pe->unlink();

        StoreEntry *const pe2 = getEntry(i);
        CPPUNIT_ASSERT(pe2 == NULL);
    }
}
