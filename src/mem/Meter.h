/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_MEM_METER_H
#define SQUID_SRC_MEM_METER_H

#include "SquidTime.h"

namespace Mem
{

/**
 * object to track per-action memory usage (e.g. #idle objects)
 */
class Meter
{
public:
    Meter() : level(0), hwater_level(0), hwater_stamp(0) {}

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
            hwater_stamp = squid_curtime ? squid_curtime : time(NULL);
        }
    }

    ssize_t level;          ///< current level (count or volume)
    ssize_t hwater_level;   ///< high water mark
    time_t hwater_stamp;    ///< timestamp of last high water mark change
};

} // namespace Mem

#endif /* SQUID_SRC_MEM_METER_H */

