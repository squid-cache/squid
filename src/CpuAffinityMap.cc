/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 54    Interprocess Communication */

#include "squid.h"
#include "base/TextException.h"
#include "CpuAffinityMap.h"
#include "CpuAffinitySet.h"
#include "Debug.h"

bool
CpuAffinityMap::add(const std::vector<int> &aProcesses, const std::vector<int> &aCores)
{
    if (aProcesses.size() != aCores.size())
        return false;

    for (size_t i = 0; i < aProcesses.size(); ++i) {
        const int process = aProcesses[i];
        const int core = aCores[i];
        if (process <= 0 || core <= 0)
            return false;
        theProcesses.push_back(process);
        theCores.push_back(core);
    }

    return true;
}

CpuAffinitySet *
CpuAffinityMap::calculateSet(const int targetProcess) const
{
    Must(theProcesses.size() == theCores.size());
    int core = 0;
    for (size_t i = 0; i < theProcesses.size(); ++i) {
        const int process = theProcesses[i];
        if (process == targetProcess) {
            if (core > 0) {
                debugs(54, DBG_CRITICAL, "WARNING: conflicting "
                       "'cpu_affinity_map' for process number " << process <<
                       ", using the last core seen: " << theCores[i]);
            }
            core = theCores[i];
        }
    }
    CpuAffinitySet *cpuAffinitySet = NULL;
    if (core > 0) {
        cpuAffinitySet = new CpuAffinitySet;
        cpu_set_t cpuSet;
        CPU_ZERO(&cpuSet);
        CPU_SET(core - 1, &cpuSet);
        cpuAffinitySet->set(cpuSet);
    }
    return cpuAffinitySet;
}

