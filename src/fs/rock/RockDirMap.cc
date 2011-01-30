/*
 * $Id$
 *
 * DEBUG: section 79    Disk IO Routines
 */

#include "squid.h"
#include "fs/rock/RockDirMap.h"

static const char SharedMemoryName[] = "RockDirMap";

Rock::DirMap::DirMap(const int id, const int limit):
    shm(SharedMemoryName, id)
{
    shm.create(limit);
    assert(shm.mem());
    shared = new (shm.mem()) Shared(limit);
}

Rock::DirMap::DirMap(const int id):
    shm(SharedMemoryName, id)
{
    shm.open();
    assert(shm.mem());
    shared = reinterpret_cast<Shared *>(shm.mem());
}

int
Rock::DirMap::entryLimit() const
{
    return shared->limit;
}

int
Rock::DirMap::entryCount() const
{
    return shared->count;
}

bool
Rock::DirMap::full() const
{
    return entryCount() >= entryLimit();
}

bool
Rock::DirMap::valid(const int pos) const
{
    return 0 <= pos && pos < entryLimit();
}

int
Rock::DirMap::useNext()
{
    assert(!full());
    const int next = findNext();
    assert(valid(next)); // because we were not full
    use(next);
    return next;
}

int
Rock::DirMap::AbsoluteEntryLimit()
{
    const int sfilenoMax = 0xFFFFFF; // Core sfileno maximum
    return sfilenoMax;
}

void
Rock::DirMap::use(const int pos)
{
    if (!has(pos)) {
        assert(valid(pos));
        shared->slots[pos] = 1;
        ++shared->count;
        debugs(8, 6, HERE << pos);
    } else {
        debugs(8, 3, HERE << pos << " in vain");
    }
}

void
Rock::DirMap::clear(const int pos)
{
    if (has(pos)) {
        shared->slots[pos] = 0;
        --shared->count;
        debugs(8, 6, HERE << pos);
    } else {
        debugs(8, 3, HERE << pos << " in vain");
        assert(valid(pos));
    }
    if (shared->hintPast < 0)
        shared->hintPast = pos; // remember cleared slot
}

bool
Rock::DirMap::has(const int pos) const
{
    if (!valid(pos)) // the only place where we are forgiving
        return false;

    return shared->slots[pos];
}

/// low-level empty-slot search routine, uses and updates hints
int
Rock::DirMap::findNext() const
{
    // try the clear-based hint, if any
    if (shared->hintPast >= 0) {
        const int result = shared->hintPast;
        shared->hintPast = -1; // assume used; or we could update it in set()
        if (valid(result) && !has(result))
            return result;
    }

    // adjust and try the scan-based hint
    if (!valid(shared->hintNext))
        shared->hintNext = 0;

    for (int i = 0; i < shared->limit; ++i) {
        if (!has(shared->hintNext))
            return shared->hintNext++;

        shared->hintNext = (shared->hintNext + 1) % shared->limit;
    }

    // the map is full
    return -1;
}

int
Rock::DirMap::SharedSize(const int limit)
{
    return sizeof(Shared) + limit * sizeof(Slot);
}

Rock::DirMap::Shared::Shared(const int aLimit):
    hintPast(-1), hintNext(0), limit(aLimit), count(0)
{
}
