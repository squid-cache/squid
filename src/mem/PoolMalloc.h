/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID__SRC_MEM_POOLMALLOC_H
#define SQUID__SRC_MEM_POOLMALLOC_H

#include "mem/AllocatorMetrics.h"

#include <stack>

namespace Mem
{

class PoolMalloc : public AllocatorMetrics
{
public:
    PoolMalloc(char const *label, size_t aSize);
    virtual ~PoolMalloc();

    /* Mem::AllocatorBase API */
    virtual int getStats(PoolStats *) override;
    virtual int getInUseCount() override;

    /* Mem::AllocatorMetrics API */
    virtual bool idleTrigger(int) const override;
    virtual void clean(time_t) override;
protected:
    virtual void *allocate() override;
    virtual void deallocate(void *, bool) override;

private:
    std::stack<void *> freelist;
};

} // namespace Mem

#endif /* SQUID__SRC_MEM_POOLMALLOC_H */

