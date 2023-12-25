/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_CPU_AFFINITY_MAP_H
#define SQUID_CPU_AFFINITY_MAP_H

#include <vector>

class CpuAffinitySet;

/// stores cpu_affinity_map configuration
class CpuAffinityMap
{
public:
    /// append cpu_affinity_map option
    bool add(const std::vector<int> &aProcesses, const std::vector<int> &aCores);

    /// calculate CPU set for this process
    CpuAffinitySet *calculateSet(const int targetProcess) const;

    /// returns list of process numbers
    const std::vector<int> &processes() const { return theProcesses; }

    /// returns list of cores
    const std::vector<int> &cores() const { return theCores; }

private:
    std::vector<int> theProcesses; ///< list of process numbers
    std::vector<int> theCores; ///< list of cores
};

#endif // SQUID_CPU_AFFINITY_MAP_H

