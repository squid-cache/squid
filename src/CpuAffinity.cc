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
#include "CpuAffinity.h"
#include "CpuAffinityMap.h"
#include "CpuAffinitySet.h"
#include "Debug.h"
#include "globals.h"
#include "SquidConfig.h"
#include "tools.h"

#include <algorithm>

static CpuAffinitySet *TheCpuAffinitySet = NULL;

void
CpuAffinityInit()
{
    Must(!TheCpuAffinitySet);
    if (Config.cpuAffinityMap) {
        const int processNumber = InDaemonMode() ? KidIdentifier : 1;
        TheCpuAffinitySet = Config.cpuAffinityMap->calculateSet(processNumber);
        if (TheCpuAffinitySet)
            TheCpuAffinitySet->apply();
    }
}

void
CpuAffinityReconfigure()
{
    if (TheCpuAffinitySet) {
        TheCpuAffinitySet->undo();
        delete TheCpuAffinitySet;
        TheCpuAffinitySet = NULL;
    }
    CpuAffinityInit();
}

void
CpuAffinityCheck()
{
    if (Config.cpuAffinityMap) {
        Must(!Config.cpuAffinityMap->processes().empty());
        const int maxProcess =
            *std::max_element(Config.cpuAffinityMap->processes().begin(),
                              Config.cpuAffinityMap->processes().end());

        // in no-deamon mode, there is one process regardless of squid.conf
        const int numberOfProcesses = InDaemonMode() ? NumberOfKids() : 1;

        if (maxProcess > numberOfProcesses) {
            debugs(54, DBG_IMPORTANT, "WARNING: 'cpu_affinity_map' has "
                   "non-existing process number(s)");
        }
    }
}

