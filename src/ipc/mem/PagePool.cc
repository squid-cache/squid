/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 54    Interprocess Communication */

#include "squid.h"
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
    pageIndex(shm_old(PageStack)(id)),
    theLevels(reinterpret_cast<Levels_t *>(
                  reinterpret_cast<char *>(pageIndex.getRaw()) +
                  pageIndex->stackSize() + pageIndex->levelsPaddingSize())),
    theBuf(reinterpret_cast<char *>(theLevels + PageId::maxPurpose))
{
}

size_t
Ipc::Mem::PagePool::level(const int purpose) const
{
    Must(0 <= purpose && purpose < PageId::maxPurpose);
    return theLevels[purpose];
}

bool
Ipc::Mem::PagePool::get(const PageId::Purpose purpose, PageId &page)
{
    Must(0 <= purpose && purpose < PageId::maxPurpose);
    if (pageIndex->pop(page)) {
        page.purpose = purpose;
        ++theLevels[purpose];
        return true;
    }
    return false;
}

void
Ipc::Mem::PagePool::put(PageId &page)
{
    if (!page)
        return;

    Must(0 <= page.purpose && page.purpose < PageId::maxPurpose);
    --theLevels[page.purpose];
    page.purpose = PageId::maxPurpose;
    return pageIndex->push(page);
}

char *
Ipc::Mem::PagePool::pagePointer(const PageId &page)
{
    Must(pageIndex->pageIdIsValid(page));
    return theBuf + pageSize() * (page.number - 1);
}

