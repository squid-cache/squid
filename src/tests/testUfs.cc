/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "DiskIO/DiskIOModule.h"
#include "fde.h"
#include "fs/ufs/UFSSwapDir.h"
#include "globals.h"
#include "HttpHeader.h"
#include "HttpReply.h"
#include "MemObject.h"
#include "RequestFlags.h"
#include "SquidConfig.h"
#include "Store.h"
#include "store/Disks.h"
#include "testStoreSupport.h"
#include "testUfs.h"
#include "unitTestMain.h"

#include <stdexcept>

#define TESTDIR "testUfs_Store"

CPPUNIT_TEST_SUITE_REGISTRATION( testUfs );

typedef RefCount<Fs::Ufs::UFSSwapDir> MySwapDirPointer;
extern REMOVALPOLICYCREATE createRemovalPolicy_lru; /* XXX fails with --enable-removal-policies=heap */

static void
addSwapDir(MySwapDirPointer aStore)
{
    allocate_new_swapdir(&Config.cacheSwap);
    Config.cacheSwap.swapDirs[Config.cacheSwap.n_configured] = aStore.getRaw();
    ++Config.cacheSwap.n_configured;
}

static bool cbcalled;

static void
searchCallback(void *cbdata)
{
    cbcalled = true;
}

void
testUfs::commonInit()
{
    static bool inited = false;

    if (inited)
        return;

    Config.Store.avgObjectSize = 1024;
    Config.Store.objectsPerBucket = 20;
    Config.Store.maxObjectSize = 2048;

    Config.store_dir_select_algorithm = xstrdup("round-robin");

    Config.replPolicy = new RemovalPolicySettings;
    Config.replPolicy->type = xstrdup("lru");

    Config.memShared.defaultTo(false);

    /* garh garh */
    storeReplAdd("lru", createRemovalPolicy_lru);

    Mem::Init();

    fde::Init();

    comm_init();

    httpHeaderInitModule(); /* must go before any header processing (e.g. the one in errorInitialize) */

    inited = true;
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

    if (0 > system ("rm -rf " TESTDIR))
        throw std::runtime_error("Failed to clean test work directory");

    Store::Init();

    MySwapDirPointer aStore (new Fs::Ufs::UFSSwapDir("ufs", "Blocking"));

    aStore->IO = new Fs::Ufs::UFSStrategy(DiskIOModule::Find("Blocking")->createStrategy());

    addSwapDir(aStore);

    commonInit();
    mem_policy = createRemovalPolicy(Config.replPolicy);

    char *path=xstrdup(TESTDIR);

    char *config_line=xstrdup("100 1 1");

    visible_appname_string = xstrdup(PACKAGE "/" VERSION);

    ConfigParser::SetCfgLine(config_line);

    aStore->parse(0, path);
    store_maxobjsize = 1024*1024*2;

    safe_free(path);

    safe_free(config_line);

    /* ok, ready to create */
    aStore->create();

    /* ok, ready to use - inits store & hash too */
    Store::Root().init();

    /* our swapdir must be scheduled to rebuild */
    CPPUNIT_ASSERT_EQUAL(2, StoreController::store_dirs_rebuilding);

    /* rebuild is a scheduled event */
    StockEventLoop loop;

    while (StoreController::store_dirs_rebuilding)
        loop.runOnce();

    /* cannot use loop.run(); as the loop will never idle: the store-dir
     * clean() scheduled event prevents it
     */

    /* nothing left to rebuild */
    CPPUNIT_ASSERT_EQUAL(0, StoreController::store_dirs_rebuilding);

    /* add an entry */
    {
        /* Create "vary" base object */
        RequestFlags flags;
        flags.cachable = true;
        StoreEntry *pe = storeCreateEntry("dummy url", "dummy log url", flags, Http::METHOD_GET);
        auto &reply = pe->mem().adjustableBaseReply();
        reply.setHeaders(Http::scOkay, "dummy test object", "x-squid-internal/test", 0, -1, squid_curtime + 100000);

        pe->setPublicKey();

        pe->buffer();
        pe->mem().freshestReply().packHeadersUsingSlowPacker(*pe);
        pe->flush();
        pe->timestampsSet();
        pe->complete();
        pe->swapOut();
        CPPUNIT_ASSERT_EQUAL(0, pe->swap_dirn);
        CPPUNIT_ASSERT_EQUAL(0, pe->swap_filen);
        pe->unlock("testUfs::testUfsSearch vary");
    }

    storeDirWriteCleanLogs(0);

    /* here we cheat: we know that UFSSwapDirs search off disk. If we did an init call to a new
     * swapdir instance, we'd not be testing a clean build.
     */
    StoreSearchPointer search = Store::Root().search(); /* search for everything in the store */

    /* nothing should be immediately available */
#if 0

    CPPUNIT_ASSERT_EQUAL(false, search->next());
#endif

    CPPUNIT_ASSERT_EQUAL(false, search->error());
    CPPUNIT_ASSERT_EQUAL(false, search->isDone());
    CPPUNIT_ASSERT_EQUAL(static_cast<StoreEntry *>(NULL), search->currentItem());

    /* trigger a callback */
    cbcalled = false;
    search->next(searchCallback, NULL);
    CPPUNIT_ASSERT_EQUAL(true, cbcalled);

    /* we should have access to a entry now, that matches the entry we had before */
    //CPPUNIT_ASSERT_EQUAL(false, search->next());
    CPPUNIT_ASSERT_EQUAL(false, search->error());
    CPPUNIT_ASSERT_EQUAL(false, search->isDone());
    CPPUNIT_ASSERT(search->currentItem() != NULL);

    /* trigger another callback */
    cbcalled = false;
    search->next(searchCallback, NULL);
    CPPUNIT_ASSERT_EQUAL(true, cbcalled);

    /* now we should have no error, we should have finished and have no current item */
    //CPPUNIT_ASSERT_EQUAL(false, search->next());
    CPPUNIT_ASSERT_EQUAL(false, search->error());
    CPPUNIT_ASSERT_EQUAL(true, search->isDone());
    CPPUNIT_ASSERT_EQUAL(static_cast<StoreEntry *>(NULL), search->currentItem());

    Store::FreeMemory();

    free_cachedir(&Config.cacheSwap);

    // TODO: here we should test a dirty rebuild

    safe_free(Config.replPolicy->type);
    delete Config.replPolicy;

    if (0 > system ("rm -rf " TESTDIR))
        throw std::runtime_error("Failed to clean test work directory");
}

/* The UFS store should always configure an IO engine even if none is
 * supplied on the configuration line.
 */
void
testUfs::testUfsDefaultEngine()
{
    /* boring common test boilerplate */
    if (0 > system ("rm -rf " TESTDIR))
        throw std::runtime_error("Failed to clean test work directory");

    // This assertion may fail if previous test cases fail.
    // Apparently, CPPUNIT_ASSERT* failure may prevent destructors of local
    // objects such as "StorePointer aRoot" from being called.
    CPPUNIT_ASSERT(!store_table); // or StoreHashIndex ctor will abort below

    Store::Init();
    MySwapDirPointer aStore (new Fs::Ufs::UFSSwapDir("ufs", "Blocking"));
    addSwapDir(aStore);
    commonInit();
    Config.replPolicy = new RemovalPolicySettings;
    Config.replPolicy->type = xstrdup("lru");
    mem_policy = createRemovalPolicy(Config.replPolicy);

    char *path=xstrdup(TESTDIR);
    char *config_line=xstrdup("100 1 1");
    ConfigParser::SetCfgLine(config_line);
    aStore->parse(0, path);
    safe_free(path);
    safe_free(config_line);
    CPPUNIT_ASSERT(aStore->IO->io != NULL);

    Store::FreeMemory();
    free_cachedir(&Config.cacheSwap);
    safe_free(Config.replPolicy->type);
    delete Config.replPolicy;

    if (0 > system ("rm -rf " TESTDIR))
        throw std::runtime_error("Failed to clean test work directory");
}

