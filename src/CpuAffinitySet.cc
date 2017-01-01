/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 54    Interprocess Communication */

#include "squid.h"
#include "base/TextException.h"
#include "CpuAffinitySet.h"
#include "Debug.h"
#include "util.h"

#include <cerrno>
#include <cstring>

CpuAffinitySet::CpuAffinitySet()
{
    CPU_ZERO(&theCpuSet);
    CPU_ZERO(&theOrigCpuSet);
}

void
CpuAffinitySet::apply()
{
    Must(CPU_COUNT(&theCpuSet) > 0); // CPU affinity mask set
    Must(!applied());

    bool success = false;
    if (sched_getaffinity(0, sizeof(theOrigCpuSet), &theOrigCpuSet)) {
        int xerrno = errno;
        debugs(54, DBG_IMPORTANT, "ERROR: failed to get CPU affinity for "
               "process PID " << getpid() << ", ignoring CPU affinity for "
               "this process: " << xstrerr(xerrno));
    } else {
        cpu_set_t cpuSet;
        memcpy(&cpuSet, &theCpuSet, sizeof(cpuSet));
        (void) CPU_AND(&cpuSet, &cpuSet, &theOrigCpuSet);
        if (CPU_COUNT(&cpuSet) <= 0) {
            debugs(54, DBG_IMPORTANT, "ERROR: invalid CPU affinity for process "
                   "PID " << getpid() << ", may be caused by an invalid core in "
                   "'cpu_affinity_map' or by external affinity restrictions");
        } else if (sched_setaffinity(0, sizeof(cpuSet), &cpuSet)) {
            int xerrno = errno;
            debugs(54, DBG_IMPORTANT, "ERROR: failed to set CPU affinity for "
                   "process PID " << getpid() << ": " << xstrerr(xerrno));
        } else
            success = true;
    }
    if (!success)
        CPU_ZERO(&theOrigCpuSet);
}

void
CpuAffinitySet::undo()
{
    if (applied()) {
        if (sched_setaffinity(0, sizeof(theOrigCpuSet), &theOrigCpuSet)) {
            int xerrno = errno;
            debugs(54, DBG_IMPORTANT, "ERROR: failed to restore original CPU "
                   "affinity for process PID " << getpid() << ": " <<
                   xstrerr(xerrno));
        }
        CPU_ZERO(&theOrigCpuSet);
    }
}

bool
CpuAffinitySet::applied()
{
    // NOTE: cannot be const.
    // According to CPU_SET(3) and, apparently, on some systems (e.g.,
    // OpenSuSE 10.3) CPU_COUNT macro expects a non-const argument.
    return (CPU_COUNT(&theOrigCpuSet) > 0);
}

void
CpuAffinitySet::set(const cpu_set_t &aCpuSet)
{
    memcpy(&theCpuSet, &aCpuSet, sizeof(theCpuSet));
}

