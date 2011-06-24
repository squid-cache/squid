/*
 * $Id$
 *
 * DEBUG: section 54    Interprocess Communication
 *
 */

#include "config.h"
#include "base/TextException.h"
#include "base/RunnersRegistry.h"
#include "ipc/mem/PagePool.h"
#include "ipc/mem/Pages.h"
#include "structs.h"
#include "SwapDir.h"

// Uses a single PagePool instance, for now.
// Eventually, we may have pools dedicated to memory caching, disk I/O, etc.

// TODO: make pool id more unique so it does not conflict with other Squids?
static const char *PagePoolId = "squid-page-pool";
static Ipc::Mem::PagePool *ThePagePool = 0;

// TODO: make configurable to avoid waste when mem-cached objects are small/big
size_t
Ipc::Mem::PageSize() {
    return 32*1024;
}

bool
Ipc::Mem::GetPage(PageId &page)
{
    return ThePagePool ? ThePagePool->get(page) : false;
}

void
Ipc::Mem::PutPage(PageId &page)
{
    Must(ThePagePool);
    ThePagePool->put(page);
}

char *
Ipc::Mem::PagePointer(const PageId &page)
{
    Must(ThePagePool);
    return ThePagePool->pagePointer(page);
}

size_t
Ipc::Mem::PageLimit()
{
    return ThePagePool ? ThePagePool->capacity() : 0;
}

size_t
Ipc::Mem::CachePageLimit()
{
    // TODO: adjust cache_mem description to say that in SMP mode,
    // in-transit objects are not allocated using cache_mem. Eventually,
    // they should not use cache_mem even if shared memory is not used:
    // in-transit objects have nothing to do with caching.
    return Config.memMaxSize > 0 ? Config.memMaxSize / PageSize() : 0;
}

size_t
Ipc::Mem::IoPageLimit()
{
    // XXX: this should be independent from memory cache pages
    return CachePageLimit();
}

size_t
Ipc::Mem::PageLevel()
{
    return ThePagePool ? ThePagePool->capacity() - ThePagePool->size() : 0;
}

size_t
Ipc::Mem::CachePageLevel()
{
    // TODO: make a separate counter for shared memory pages for memory cache
    return PageLevel();
}

size_t
Ipc::Mem::IoPageLevel()
{
    // TODO: make a separate counter for shared memory pages for IPC I/O
    return PageLevel();
}

/// initializes shared memory pages
class SharedMemPagesRr: public RegisteredRunner
{
public:
    /* RegisteredRunner API */
    SharedMemPagesRr(): owner(NULL) {}
    virtual void run(const RunnerRegistry &);
    virtual ~SharedMemPagesRr();

private:
    Ipc::Mem::PagePool::Owner *owner;
};

RunnerRegistrationEntry(rrAfterConfig, SharedMemPagesRr);


void SharedMemPagesRr::run(const RunnerRegistry &)
{
    if (!UsingSmp())
        return;

    // When cache_dirs start using shared memory pages, they would
    // need to communicate their needs to us somehow.
    if (Config.memMaxSize <= 0)
        return;

    if (Ipc::Mem::CachePageLimit() <= 0) {
        if (IamMasterProcess()) {
            debugs(54, DBG_IMPORTANT, "WARNING: mem-cache size is too small ("
                   << (Config.memMaxSize / 1024.0) << " KB), should be >= " <<
                   (Ipc::Mem::PageSize() / 1024.0) << " KB");
        }
        return;
    }

    if (IamMasterProcess()) {
        Must(!owner);
        // reserve 10% for IPC I/O
        const size_t capacity = Ipc::Mem::CachePageLimit() * 1.1;
        owner = Ipc::Mem::PagePool::Init(PagePoolId, capacity, Ipc::Mem::PageSize());
    }

    Must(!ThePagePool);
    ThePagePool = new Ipc::Mem::PagePool(PagePoolId);
}

SharedMemPagesRr::~SharedMemPagesRr()
{
    if (!UsingSmp())
        return;

    delete ThePagePool;
    ThePagePool = NULL;
    delete owner;
}
