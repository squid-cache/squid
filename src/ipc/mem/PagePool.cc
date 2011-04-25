/*
 * $Id$
 *
 * DEBUG: section 54    Interprocess Communication
 *
 */

#include "config.h"
#include "base/TextException.h"
#include "ipc/mem/Page.h"
#include "ipc/mem/PagePool.h"


// Ipc::Mem::PagePool

Ipc::Mem::PagePool::Owner *
Ipc::Mem::PagePool::Init(const char *const id, const unsigned int capacity, const size_t pageSize)
{
    static uint32_t LastPagePoolId = 0;
    if (++LastPagePoolId == 0)
        ++LastPagePoolId; // skip zero pool id
    return shm_new(PageStack)(id, LastPagePoolId, capacity, pageSize);
}

Ipc::Mem::PagePool::PagePool(const char *const id):
    pageIndex(shm_old(PageStack)(id))
{
    const size_t pagesDataOffset =
        pageIndex->sharedMemorySize() - capacity() * pageSize();
    theBuf = reinterpret_cast<char *>(pageIndex.getRaw()) + pagesDataOffset;
}

void *
Ipc::Mem::PagePool::pagePointer(const PageId &page)
{
    Must(pageIndex->pageIdIsValid(page));
    return theBuf + pageSize() * (page.number - 1);
}
