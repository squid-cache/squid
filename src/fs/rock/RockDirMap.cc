/*
 * $Id$
 *
 * DEBUG: section 79    Disk IO Routines
 */

#include "squid.h"
#include "fs/rock/RockDirMap.h"

Rock::DirMap::DirMap(const int aLimit): hintPast(-1), hintNext(0),
    limit(aLimit), count(0), slots(NULL)
{
    allocate();
}

Rock::DirMap::DirMap(const DirMap &m):
    hintPast(m.hintPast), hintNext(m.hintNext),
    limit(m.limit), count(m.count),
    slots(NULL)
{
    copyFrom(m);
}

Rock::DirMap::~DirMap()
{
    deallocate();
}

Rock::DirMap &Rock::DirMap::operator =(const DirMap &m)
{
    deallocate();

    hintPast = m.hintPast;
    hintNext = m.hintNext;
    limit = m.limit;
    count = m.count;

    copyFrom(m);
    return *this;
}

void
Rock::DirMap::resize(const int newLimit)
{
    // TODO: optimize?
    if (newLimit != limit) {
        DirMap old(*this);
        deallocate();
        limit = newLimit;
        copyFrom(old);
	}
}

int
Rock::DirMap::entryLimit() const
{
    return limit;
}

int
Rock::DirMap::entryCount() const
{
    return count;
}

bool
Rock::DirMap::full() const
{
    return count >= limit;
}

bool
Rock::DirMap::valid(const int pos) const
{
    return 0 <= pos && pos < limit;
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

/// allocation, assumes limit is set
void
Rock::DirMap::allocate()
{
    assert(!slots);
    slots = new uint8_t[limit];
    memset(slots, 0, ramSize());
}

/// deallocation; may place the object in an inconsistent state
void
Rock::DirMap::deallocate()
{
    delete [] slots;
    slots = NULL;
}

/// low-level copy; assumes all counts have been setup
void
Rock::DirMap::copyFrom(const DirMap &m)
{
    allocate();
    if (m.limit)
        memcpy(slots, m.slots, min(ramSize(), m.ramSize()));
}

/// low-level ram size calculation for mem*() calls
int
Rock::DirMap::ramSize() const
{
    return sizeof(*slots) * limit;
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
        slots[pos] = 1;
        ++count;
        debugs(8, 6, HERE << pos);
	} else {
        debugs(8, 3, HERE << pos << " in vain");
	}
}

void
Rock::DirMap::clear(const int pos)
{
    if (has(pos)) {
        slots[pos] = 0;
        --count;
        debugs(8, 6, HERE << pos);
	} else {
        debugs(8, 3, HERE << pos << " in vain");
        assert(valid(pos));
	}
    if (hintPast < 0)
        hintPast = pos; // remember cleared slot
}

bool
Rock::DirMap::has(const int pos) const
{
    if (!valid(pos)) // the only place where we are forgiving
        return false;

    return slots[pos];
}

/// low-level empty-slot search routine, uses and updates hints
int
Rock::DirMap::findNext() const
{
    // try the clear-based hint, if any
    if (hintPast >= 0) {
        const int result = hintPast;
        hintPast = -1; // assume used; or we could update it in set()
        if (valid(result) && !has(result))
            return result;
	}

    // adjust and try the scan-based hint
    if (!valid(hintNext))
        hintNext = 0;

    for (int i = 0; i < limit; ++i) {
        if (!has(hintNext))
            return hintNext++;

        hintNext = (hintNext + 1) % limit;
    }

    // the map is full
    return -1;
}
