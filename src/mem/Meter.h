/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_MEM_METER_H
#define SQUID_SRC_MEM_METER_H

#include "time/gadgets.h"

namespace Mem
{

/**
 * object to track per-action memory usage (e.g. #idle objects)
 */
class Meter
{
public:
    /// flush the meter level back to 0, but leave peak records
    void flush() {level=0;}

    ssize_t currentLevel() const {return level;}
    ssize_t peak() const {return hwater_level;}
    time_t peakTime() const {return hwater_stamp;}

    Meter &operator ++() {++level; checkHighWater(); return *this;}
    Meter &operator --() {--level; return *this;}

    Meter &operator +=(ssize_t n) { level += n; checkHighWater(); return *this;}
    Meter &operator -=(ssize_t n) { level -= n; return *this;}

private:
    /// check the high-water level of this meter and raise if necessary
    /// recording the timestamp of last high-water peak change
    void checkHighWater() {
        if (hwater_level < level) {
            hwater_level = level;
            hwater_stamp = squid_curtime ? squid_curtime : time(nullptr);
        }
    }

    ssize_t level = 0; ///< current level (count or volume)
    ssize_t hwater_level = 0; ///< high water mark
    time_t hwater_stamp = 0; ///< timestamp of last high water mark change
};

/**
 * Object to track per-pool memory usage (alloc = inuse+idle)
 */
class PoolMeter
{
public:
    /// Object to track per-pool cumulative counters
    class mgb_t
    {
    public:
        mgb_t &operator +=(const mgb_t &o) {
            count += o.count;
            bytes += o.bytes;
            return *this;
        }

        /// account for memory actions taking place
        void update(size_t items, size_t itemSize) {
            count += items;
            bytes += (items * itemSize);
        }

    public:
        double count = 0.0;
        double bytes = 0.0;
    };

    /// flush counters back to 0, but leave historic peak records
    void flush() {
        alloc.flush();
        inuse.flush();
        idle.flush();
        gb_allocated = mgb_t();
        gb_oallocated = mgb_t();
        gb_saved = mgb_t();
        gb_freed = mgb_t();
    }

    Meter alloc;
    Meter inuse;
    Meter idle;

    /** history Allocations */
    mgb_t gb_allocated;
    mgb_t gb_oallocated;

    /** account Saved Allocations */
    mgb_t gb_saved;

    /** account Free calls */
    mgb_t gb_freed;
};

} // namespace Mem

#endif /* SQUID_SRC_MEM_METER_H */

