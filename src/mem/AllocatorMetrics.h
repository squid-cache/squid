/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID__SRC_MEM_ALLOCATORMETRICS_H
#define SQUID__SRC_MEM_ALLOCATORMETRICS_H

#include "mem/AllocatorBase.h"
#include "mem/Meter.h"

namespace Mem
{

/// Object to track per-pool memory usage (alloc = inuse+idle)
class PoolMeter
{
public:
    /// Object to track per-pool cumulative counters
    class mgb_t
    {
    public:
        double count = 0.0;
        double bytes = 0.0;
    };

    PoolMeter() {flush();}

    void flush();

    Mem::Meter alloc;
    Mem::Meter inuse;
    Mem::Meter idle;

    /** history Allocations */
    mgb_t gb_allocated;
    mgb_t gb_oallocated;

    /** account Saved Allocations */
    mgb_t gb_saved;

    /** account Free calls */
    mgb_t gb_freed;
};

/// Interface for managing memory allocation statistics
class AllocatorMetrics : public Mem::AllocatorBase
{
public:
    AllocatorMetrics(char const *aLabel, size_t aSize);
    virtual ~AllocatorMetrics();

    virtual PoolMeter &getMeter() {return meter;}
    virtual void flushMetersFull();
    /// update all pool counters, and recreate TheMeter totals from all pools
    virtual void flushMeters();
    virtual bool idleTrigger(int shift) const = 0;
    virtual void clean(time_t maxage) = 0;

    /* Mem::AllocatorBase API */
    virtual PoolMeter const &getMeter() const override {return meter;}
    virtual void *alloc() override;
    virtual void freeOne(void *) override;
    virtual size_t objectSize() const override {return obj_size;}

protected:
    virtual void *allocate() = 0;
    virtual void deallocate(void *, bool aggressive) = 0;

    PoolMeter meter;
    int memPID = 0;

public:
    size_t alloc_calls = 0;
    size_t free_calls = 0;
    size_t saved_calls = 0;
    size_t obj_size = 0;
};

} // namespace Mem

#endif /* SQUID__SRC_MEM_ALLOCATORMETRICS_H */
