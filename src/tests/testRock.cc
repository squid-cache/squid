/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "ConfigParser.h"
#include "DiskIO/DiskIOModule.h"
#include "fs/rock/RockSwapDir.h"
#include "globals.h"
#include "HttpHeader.h"
#include "HttpReply.h"
#include "MemObject.h"
#include "RequestFlags.h"
#include "SquidConfig.h"
#include "Store.h"
#include "store/Disk.h"
#include "store/Disks.h"
#include "StoreFileSystem.h"
#include "StoreSearch.h"
#include "testRock.h"
#include "testStoreSupport.h"
#include "unitTestMain.h"

#include <stdexcept>
#if HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif
#if HAVE_UNISTD_H
#include <unistd.h>
#endif

#define TESTDIR "tr"

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

    Config.memShared.defaultTo(false);
    Config.shmLocking.defaultTo(false);

    // use current directory for shared segments (on path-based OSes)
    Ipc::Mem::Segment::BasePath = getcwd(cwd,MAXPATHLEN);
    if (Ipc::Mem::Segment::BasePath == NULL)
        Ipc::Mem::Segment::BasePath = ".";

    Store::Init();

    store = new Rock::SwapDir();

    addSwapDir(store);

    commonInit();

    char *path=xstrdup(TESTDIR);

    char *config_line=xstrdup("10 max-size=16384");

    ConfigParser::SetCfgLine(config_line);

    store->parse(0, path);
    store_maxobjsize = 1024*1024*2;

    safe_free(path);

    safe_free(config_line);

    /* ok, ready to create */
    store->create();

    rr = new Rock::SwapDirRr;
    rr->useConfig();
}

void
testRock::tearDown()
{
    CPPUNIT_NS::TestFixture::tearDown();

    Store::FreeMemory();

    store = NULL;

    free_cachedir(&Config.cacheSwap);

    rr->finishShutdown(); // deletes rr
    rr = NULL;

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
    Config.replPolicy->type = xstrdup("lru");
    Config.replPolicy->args = NULL;

    /* garh garh */
    storeReplAdd("lru", createRemovalPolicy_lru);

    visible_appname_string = xstrdup(APP_FULLNAME);

    Mem::Init();

    comm_init();

    httpHeaderInitModule(); /* must go before any header processing (e.g. the one in errorInitialize) */

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
    CPPUNIT_ASSERT_EQUAL(0, StoreController::store_dirs_rebuilding);
}

static const char *
storeId(const int i)
{
    static char buf[64];
    snprintf(buf, sizeof(buf), "dummy url %i", i);
    buf[sizeof(buf) - 1] = '\0';
    return buf;
}

StoreEntry *
testRock::createEntry(const int i)
{
    RequestFlags flags;
    flags.cachable = true;
    StoreEntry *const pe =
        storeCreateEntry(storeId(i), "dummy log url", flags, Http::METHOD_GET);
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
    pe->getReply()->packHeadersInto(pe);
    pe->flush();
    pe->timestampsSet();
    pe->complete();
    pe->swapOut();

    return pe;
}

StoreEntry *
testRock::getEntry(const int i)
{
    return storeGetPublic(storeId(i), Http::METHOD_GET);
}

void
testRock::testRockCreate()
{
    struct stat sb;

    CPPUNIT_ASSERT_EQUAL(0, ::stat(TESTDIR, &sb));

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

        CPPUNIT_ASSERT_EQUAL(SWAPOUT_WRITING, pe->swap_status);
        CPPUNIT_ASSERT_EQUAL(0, pe->swap_dirn);
        CPPUNIT_ASSERT(pe->swap_filen >= 0);

        // Rock::IoState::finishedWriting() schedules an AsyncCall
        // storeSwapOutFileClosed().  Let it fire.
        StockEventLoop loop;
        loop.run();

        CPPUNIT_ASSERT_EQUAL(SWAPOUT_DONE, pe->swap_status);

        pe->unlock("testRock::testRockSwapOut priming");
    }

    CPPUNIT_ASSERT_EQUAL((uint64_t)5, store->currentCount());

    // try to swap out entry to a used unlocked slot
    {
        // without marking the old entry as deleted
        StoreEntry *const pe = addEntry(3);

        CPPUNIT_ASSERT_EQUAL(SWAPOUT_NONE, pe->swap_status);
        CPPUNIT_ASSERT_EQUAL(-1, pe->swap_dirn);
        CPPUNIT_ASSERT_EQUAL(-1, pe->swap_filen);
        pe->unlock("testRock::testRockSwapOut e#3");

        // after marking the old entry as deleted
        StoreEntry *const pe2 = getEntry(4);
        CPPUNIT_ASSERT(pe2 != nullptr);
        pe2->release();

        StoreEntry *const pe3 = addEntry(4);
        CPPUNIT_ASSERT_EQUAL(SWAPOUT_WRITING, pe3->swap_status);
        CPPUNIT_ASSERT_EQUAL(0, pe3->swap_dirn);
        CPPUNIT_ASSERT(pe3->swap_filen >= 0);

        StockEventLoop loop;
        loop.run();

        CPPUNIT_ASSERT_EQUAL(SWAPOUT_DONE, pe3->swap_status);

        pe->unlock("testRock::testRockSwapOut e#4");
    }

    // try to swap out entry to a used locked slot
    {
        StoreEntry *const pe = addEntry(5);

        CPPUNIT_ASSERT_EQUAL(SWAPOUT_WRITING, pe->swap_status);
        CPPUNIT_ASSERT_EQUAL(0, pe->swap_dirn);
        CPPUNIT_ASSERT(pe->swap_filen >= 0);

        // the slot is locked here because the async calls have not run yet
        StoreEntry *const pe2 = addEntry(5);
        CPPUNIT_ASSERT_EQUAL(SWAPOUT_NONE, pe2->swap_status);
        CPPUNIT_ASSERT_EQUAL(MemObject::SwapOut::swImpossible, pe2->mem_obj->swapout.decision);
        CPPUNIT_ASSERT_EQUAL(-1, pe2->swap_dirn);
        CPPUNIT_ASSERT_EQUAL(-1, pe2->swap_filen);

        StockEventLoop loop;
        loop.run();

        pe->unlock("testRock::testRockSwapOut e#5.1");
        pe2->unlock("testRock::testRockSwapOut e#5.2");

        // pe2 has the same public key as pe so it marks old pe for release
        // here, we add another entry #5 into the now-available slot
        StoreEntry *const pe3 = addEntry(5);
        CPPUNIT_ASSERT_EQUAL(SWAPOUT_WRITING, pe3->swap_status);
        CPPUNIT_ASSERT_EQUAL(0, pe3->swap_dirn);
        CPPUNIT_ASSERT(pe3->swap_filen >= 0);
        loop.run();
        CPPUNIT_ASSERT_EQUAL(SWAPOUT_DONE, pe3->swap_status);
        pe3->unlock("testRock::testRockSwapOut e#5.3");
    }

    CPPUNIT_ASSERT_EQUAL((uint64_t)6, store->currentCount());

    // try to get and release all entries
    for (int i = 0; i < 6; ++i) {
        StoreEntry *const pe = getEntry(i);
        CPPUNIT_ASSERT(pe != NULL);

        pe->release(); // destroys pe

        StoreEntry *const pe2 = getEntry(i);
        CPPUNIT_ASSERT_EQUAL(static_cast<StoreEntry *>(NULL), pe2);
    }
}

