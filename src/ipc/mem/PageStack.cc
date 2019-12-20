/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 54    Interprocess Communication */

#include "squid.h"

#include "base/TextException.h"
#include "Debug.h"
#include "ipc/mem/Page.h"
#include "ipc/mem/PageStack.h"

/* Ipc::Mem::PageStackStorageSlot */

static_assert(sizeof(Ipc::Mem::PageStackStorageSlot::Pointer) ==
    sizeof(decltype(Ipc::Mem::PageId::number)), "page indexing types are consistent");

void
Ipc::Mem::PageStackStorageSlot::take()
{
    const auto nxt = nextOrMarker.exchange(TakenPage);
    assert(nxt != TakenPage);
}

void
Ipc::Mem::PageStackStorageSlot::put(const PointerOrMarker expected, const Pointer nxt)
{
    assert(nxt != TakenPage);
    const auto old = nextOrMarker.exchange(nxt);
    assert(old == expected);
}

/* Ipc::Mem::PageStack */

Ipc::Mem::PageStack::PageStack(const uint32_t aPoolId, const PageCount aCapacity, const size_t aPageSize):
    thePoolId(aPoolId), capacity_(aCapacity), thePageSize(aPageSize),
    size_(0),
    head_(Slot::NilPtr),
    slots_(aCapacity)
{
    assert(capacity_ < Slot::TakenPage);
    assert(capacity_ < Slot::NilPtr);

    // initially, all pages are free
    if (capacity_) {
        const auto lastIndex = capacity_-1;
        // FlexibleArray cannot construct its phantom elements so, technically,
        // all slots (except the very first one) are uninitialized until now.
        for (Slot::Pointer i = 0; i < lastIndex; ++i)
            (void)new(&slots_[i])Slot(i+1);
        (void)new(&slots_[lastIndex])Slot(Slot::NilPtr);
        size_ = capacity_;
        head_ = 0;
    }
}

bool
Ipc::Mem::PageStack::pop(PageId &page)
{
    assert(!page);

    Slot::Pointer current = head_.load();

    auto nextFree = Slot::NilPtr;
    do {
        if (current == Slot::NilPtr)
            return false;
        nextFree = slots_[current].next();
    } while (!head_.compare_exchange_weak(current, nextFree));

    // must decrement after removing the page to avoid underflow
    const auto newSize = --size_;
    assert(newSize < capacity_);

    slots_[current].take();
    page.number = current + 1;
    page.pool = thePoolId;
    debugs(54, 8, page << " size: " << newSize);
    return true;
}

void
Ipc::Mem::PageStack::push(PageId &page)
{
    debugs(54, 8, page);
    assert(page);
    assert(pageIdIsValid(page));

    const auto pageIndex = page.number - 1;
    auto &slot = slots_[pageIndex];

    // must increment before inserting the page to avoid underflow in pop()
    const auto newSize = ++size_;
    assert(newSize <= capacity_);

    auto current = head_.load();
    auto expected = Slot::TakenPage;
    do {
        slot.put(expected, current);
        expected = current;
    } while (!head_.compare_exchange_weak(current, pageIndex));

    debugs(54, 8, page << " size: " << newSize);
    page = PageId();
}

bool
Ipc::Mem::PageStack::pageIdIsValid(const PageId &page) const
{
    return page.pool == thePoolId &&
           0 < page.number && page.number <= capacity();
}

size_t
Ipc::Mem::PageStack::sharedMemorySize() const
{
    return SharedMemorySize(thePoolId, capacity_, thePageSize);
}

size_t
Ipc::Mem::PageStack::SharedMemorySize(const uint32_t, const PageCount capacity, const size_t pageSize)
{
    const auto levelsSize = PageId::maxPurpose * sizeof(Levels_t);
    const size_t pagesDataSize = capacity * pageSize;
    return StackSize(capacity) + LevelsPaddingSize(capacity) + levelsSize + pagesDataSize;
}

size_t
Ipc::Mem::PageStack::StackSize(const PageCount capacity)
{
    return sizeof(PageStack) + capacity * sizeof(Slot);
}

size_t
Ipc::Mem::PageStack::stackSize() const
{
    return StackSize(capacity_);
}

size_t
Ipc::Mem::PageStack::LevelsPaddingSize(const PageCount capacity)
{
    const auto displacement = StackSize(capacity) % alignof(Levels_t);
    return displacement ? alignof(Levels_t) - displacement : 0;
}

