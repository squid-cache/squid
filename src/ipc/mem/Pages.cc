/*
 * $Id$
 *
 * DEBUG: section 54    Interprocess Communication
 *
 */

#include "config.h"
#include "base/TextException.h"
#include "ipc/mem/PagePool.h"
#include "ipc/mem/Pages.h"
#include "structs.h"
#include "SwapDir.h"

// Uses a single PagePool instance, for now.
// Eventually, we may have pools dedicated to memory caching, disk I/O, etc.

// TODO: make pool id more unique so it does not conflict with other Squids?
static const String PagePoolId = "squid-page-pool";
static Ipc::Mem::PagePool *ThePagePool = 0;

// XXX: make configurable
size_t
Ipc::Mem::PageSize() {
	return 16*1024;
}

void
Ipc::Mem::Init()
{
    Must(!ThePagePool);
    // XXX: pool capacity and page size should be configurable/meaningful
    ThePagePool = new PagePool(PagePoolId, 1024, PageSize());
}

void
Ipc::Mem::Attach()
{
    Must(!ThePagePool);
    // TODO: make pool id more unique so it does not conflict with other Squid instances?
    ThePagePool = new PagePool(PagePoolId);
}

bool
Ipc::Mem::GetPage(PageId &page)
{
    Must(ThePagePool);
    return ThePagePool->get(page);
}

void
Ipc::Mem::PutPage(PageId &page)
{
    Must(ThePagePool);
    ThePagePool->put(page);
}

void *
Ipc::Mem::PagePointer(const PageId &page)
{
    Must(ThePagePool);
    return ThePagePool->pagePointer(page);
}
