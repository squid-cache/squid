
#ifndef _MEM_METER_H_
#define _MEM_METER_H_

typedef struct _MemMeter MemMeter;

/* object to track per-action memory usage (e.g. #idle objects) */
struct _MemMeter {
    ssize_t level;              /* current level (count or volume) */
    ssize_t hwater_level;       /* high water mark */
    time_t hwater_stamp;        /* timestamp of last high water mark change */
};

#define memMeterSyncHWater(m)  { (m).hwater_level = (m).level; (m).hwater_stamp = squid_curtime; }
#define memMeterCheckHWater(m) { if ((m).hwater_level < (m).level) memMeterSyncHWater((m)); }
#define memMeterInc(m) { (m).level++; memMeterCheckHWater(m); }
#define memMeterDec(m) { (m).level--; }
#define memMeterAdd(m, sz) { (m).level += (sz); memMeterCheckHWater(m); }
#define memMeterDel(m, sz) { (m).level -= (sz); }

#endif /* _MEM_METER_H_ */
