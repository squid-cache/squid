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


static String
PageIndexId(String id)
{
    id.append("-index");
    return id;
}


// Ipc::Mem::PagePool

Ipc::Mem::PagePool::PagePool(const String &id, const unsigned int capacity, const size_t pageSize):
    pageIndex(PageIndexId(id), capacity),
    shm(id.termedBuf())
{
    shm.create(sizeof(Shared) + pageSize*capacity);
    assert(shm.mem());
    shared = new (shm.mem()) Shared(capacity, pageSize);
}

Ipc::Mem::PagePool::PagePool(const String &id):
    pageIndex(PageIndexId(id)), shm(id.termedBuf())
{
    shm.open();
    shared = reinterpret_cast<Shared *>(shm.mem());
    assert(shared);
}

bool
Ipc::Mem::PagePool::get(PageId &page)
{
    if (pageIndex.pop(page.number)) {
        page.pool = shared->theId;
        return true;
    }
    return false;
}

void
Ipc::Mem::PagePool::put(PageId &page)
{
    Must(pageIdIsValid(page));
    pageIndex.push(page.number);
    page = PageId();
}

void *
Ipc::Mem::PagePool::pagePointer(const PageId &page)
{
    Must(pageIdIsValid(page));
    return shared->theBuf + shared->thePageSize * (page.number - 1);
}

bool
Ipc::Mem::PagePool::pageIdIsValid(const PageId &page) const
{
    return page.pool == shared->theId &&
        0 < page.number && page.number <= shared->theCapacity;
}


// Ipc::Mem::PagePool::Shared

static unsigned int LastPagePoolId = 0;

Ipc::Mem::PagePool::Shared::Shared(const unsigned int aCapacity, size_t aPageSize):
    theId(++LastPagePoolId), theCapacity(aCapacity), thePageSize(aPageSize)
{
    if (LastPagePoolId + 1 == 0)
        ++LastPagePoolId; // skip zero pool id
}
