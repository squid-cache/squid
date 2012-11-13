/*
 */

#ifndef SQUID_CPU_AFFINITY_MAP_H
#define SQUID_CPU_AFFINITY_MAP_H

#include "Array.h"

class CpuAffinitySet;

/// stores cpu_affinity_map configuration
class CpuAffinityMap
{
public:
    /// append cpu_affinity_map option
    bool add(const Vector<int> &aProcesses, const Vector<int> &aCores);

    /// calculate CPU set for this process
    CpuAffinitySet *calculateSet(const int targetProcess) const;

    /// returns list of process numbers
    const Vector<int> &processes() const { return theProcesses; }

    /// returns list of cores
    const Vector<int> &cores() const { return theCores; }

private:
    Vector<int> theProcesses; ///< list of process numbers
    Vector<int> theCores; ///< list of cores
};

#endif // SQUID_CPU_AFFINITY_MAP_H
