/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_CPU_AFFINITY_SET_H
#define SQUID_CPU_AFFINITY_SET_H

#include "compat/cpu.h"

/// cpu affinity management for a single process
class CpuAffinitySet
{
public:
    CpuAffinitySet();

    /// set CPU affinity for this process
    void apply();

    /// undo CPU affinity changes for this process
    void undo();

    /// whether apply() was called and was not undone
    bool applied();

    /// set CPU affinity mask
    void set(const cpu_set_t &aCpuSet);

private:
    cpu_set_t theCpuSet; ///< configured CPU affinity for this process
    cpu_set_t theOrigCpuSet; ///< CPU affinity for this process before apply()
};

#endif // SQUID_CPU_AFFINITY_SET_H

