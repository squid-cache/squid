/*
 * $Id$
 *
 * DEBUG: section 79    Disk IO Routines
 */

#include "squid.h"
#include "fs/rock/RockDirMap.h"

Rock::DirMap::DirMap(int roughLimit): hintPast(-1), hintNext(0),
    bitLimit(roundLimit(roughLimit)), bitCount(0), words(NULL), wordCount(0)
{
    syncWordCount();
    allocate();
}

Rock::DirMap::DirMap(const DirMap &m):
    hintPast(m.hintPast), hintNext(m.hintNext),
    bitLimit(m.bitLimit), bitCount(m.bitCount),
    words(NULL), wordCount(m.wordCount)
{
    syncWordCount();
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
    bitLimit = m.bitLimit;
    bitCount = m.bitCount;

    wordCount = m.wordCount;
    copyFrom(m);
    return *this;
}

void
Rock::DirMap::resize(const int roughLimit)
{
    const int newLimit = roundLimit(roughLimit);
    // TODO: optimize?
    if (newLimit != bitLimit) {
        DirMap old(*this);
        deallocate();
        bitLimit = newLimit;
        syncWordCount();
        copyFrom(old);
	}
}

int
Rock::DirMap::entryLimit() const
{
    return bitLimit;
}

int
Rock::DirMap::entryCount() const
{
    return bitCount;
}

bool
Rock::DirMap::full() const
{
    return bitCount >= bitLimit;
}

bool
Rock::DirMap::valid(const int pos) const
{
    return 0 <= pos && pos < bitLimit;
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

/// low-level allocation, assumes wordCount is set
void
Rock::DirMap::allocate()
{
    assert(!words);
    words = new unsigned long[wordCount];
    memset(words, 0, ramSize());
}

/// low-level deallocation; may place the object in an inconsistent state
void
Rock::DirMap::deallocate()
{
    delete[] words;
    words = NULL;
}

/// low-level copy; assumes all counts have been setup
void
Rock::DirMap::copyFrom(const DirMap &m)
{
    allocate();
    if (m.wordCount)
        memcpy(words, m.words, min(ramSize(), m.ramSize()));
}

/// low-level ram size calculation for mem*() calls
int
Rock::DirMap::ramSize() const
{
    return sizeof(*words) * wordCount;
}

/* XXX: Number of bits in a long and other constants from filemap.cc */
#if SIZEOF_LONG == 8
#define LONG_BIT_SHIFT 6
#define BITS_IN_A_LONG 0x40
#define LONG_BIT_MASK  0x3F
#define ALL_ONES (unsigned long) 0xFFFFFFFFFFFFFFFF
#elif SIZEOF_LONG == 4
#define LONG_BIT_SHIFT 5
#define BITS_IN_A_LONG 0x20
#define LONG_BIT_MASK  0x1F
#define ALL_ONES (unsigned long) 0xFFFFFFFF
#else
#define LONG_BIT_SHIFT 5
#define BITS_IN_A_LONG 0x20
#define LONG_BIT_MASK  0x1F
#define ALL_ONES (unsigned long) 0xFFFFFFFF
#endif

#define FM_INITIAL_NUMBER (1<<14)

int
Rock::DirMap::AbsoluteEntryLimit()
{
    const int sfilenoMax = 0xFFFFFF; // Core sfileno maximum
    return ((sfilenoMax+1) >> LONG_BIT_SHIFT) << LONG_BIT_SHIFT;
}

/// Adjust limit so that there are no "extra" bits in the last word
//  that are above the limit but still found by findNext.
int
Rock::DirMap::roundLimit(const int roughLimit) const
{
    const int allowedLimit = min(roughLimit, AbsoluteEntryLimit());
    const int newLimit = (allowedLimit >> LONG_BIT_SHIFT) << LONG_BIT_SHIFT;
    debugs(8, 3, HERE << "adjusted map limit from " << roughLimit << " to " <<
        newLimit);
    return newLimit;
}

/// calculate wordCount for the number of entries (bitLimit)
void
Rock::DirMap::syncWordCount()
{
    wordCount = bitLimit >> LONG_BIT_SHIFT;
    debugs(8, 3, HERE << wordCount << ' ' << BITS_IN_A_LONG <<
        "-bit long words for " << bitLimit << " bits");
}

void
Rock::DirMap::use(const int pos)
{
    if (!has(pos)) {
        assert(valid(pos));

        const unsigned long bitmask = (1L << (pos & LONG_BIT_MASK));
        words[pos >> LONG_BIT_SHIFT] |= bitmask;

        ++bitCount;
        debugs(8, 6, HERE << pos);
	} else {
        debugs(8, 3, HERE << pos << " in vain");
	}
}

void
Rock::DirMap::clear(const int pos)
{
    if (has(pos)) {
        const unsigned long bitmask = (1L << (pos & LONG_BIT_MASK));
        words[pos >> LONG_BIT_SHIFT] &= ~bitmask;
        --bitCount;
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

    const unsigned long bitmask = (1L << (pos & LONG_BIT_MASK));
    return words[pos >> LONG_BIT_SHIFT] & bitmask;
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
    if (valid(hintNext) && !has(hintNext))
        return hintNext++;

    // start scan with the scan-based hint
    int wordPos = hintNext >> LONG_BIT_SHIFT;

    for (int i = 0; i < wordCount; ++i) {
        if (words[wordPos] != ALL_ONES)
            break;

        wordPos = (wordPos + 1) % wordCount;
    }

    for (int bitPos = 0; bitPos < BITS_IN_A_LONG; ++bitPos) {
        hintNext = ((unsigned long) wordPos << LONG_BIT_SHIFT) | bitPos;

        if (hintNext < bitLimit && !has(hintNext))
            return hintNext++;
    }

    // the map is full
    return -1;
}
