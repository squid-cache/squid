/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef _MEM_METER_H_
#define _MEM_METER_H_

/* object to track per-action memory usage (e.g. #idle objects) */
class MemMeter
{
public:
    MemMeter() : level(0), hwater_level(0), hwater_stamp(0) {}
    ssize_t level;              /* current level (count or volume) */
    ssize_t hwater_level;       /* high water mark */
    time_t hwater_stamp;        /* timestamp of last high water mark change */
};

#define memMeterSyncHWater(m)  { (m).hwater_level = (m).level; (m).hwater_stamp = squid_curtime ? squid_curtime : time(NULL); }
#define memMeterCheckHWater(m) { if ((m).hwater_level < (m).level) memMeterSyncHWater((m)); }
#define memMeterInc(m) { (m).level++; memMeterCheckHWater(m); }
#define memMeterDec(m) { (m).level--; }
#define memMeterAdd(m, sz) { (m).level += (sz); memMeterCheckHWater(m); }
#define memMeterDel(m, sz) { (m).level -= (sz); }

#endif /* _MEM_METER_H_ */

