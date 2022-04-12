/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 54    Interprocess Communication */

#include "squid.h"
#include "base/RunnersRegistry.h"
#include "base/TextException.h"
#include "CpuAffinityMap.h"
#include "CpuAffinitySet.h"
#include "debug/Stream.h"
#include "globals.h"
#include "SquidConfig.h"
#include "tools.h"

#include <algorithm>

static CpuAffinitySet *TheCpuAffinitySet = nullptr;

/// Makes CPU affinity of this process match configured CPU affinity.
/// Assumes that we have never set the CPU affinity or have cleared it.
static void
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

/// reconfigure CPU affinity for this process
static void
CpuAffinityReconfigure()
{
    CpuAffinityCheck();
    if (TheCpuAffinitySet) {
        TheCpuAffinitySet->undo();
        delete TheCpuAffinitySet;
        TheCpuAffinitySet = nullptr;
    }
    CpuAffinityInit();
}

/// check CPU affinity configuration and print warnings if needed
static void
CpuAffinityCheck()
{
    if (!IamPrimaryProcess())
        return;
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

class CpuAffinityRr : public RegisteredRunner
{
public:
    virtual void finalizeConfig() override {
        CpuAffinityCheck();
    }

    virtual void useConfig() override {
        CpuAffinityInit();
    }

    virtual void syncConfig() override {
        CpuAffinityReconfigure();
    }
};

RunnerRegistrationEntry(CpuAffinityRr);

