/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 54    Interprocess Communication */

#include "squid.h"
#include "base/TextException.h"
#include "globals.h"
#include "ipc/Kids.h"
#include "SquidConfig.h"
#include "tools.h"

Kids TheKids;
SBuf TheKidName;

Kids::Kids()
{
}

/// maintain n kids
void Kids::init()
{
    storage.clear();

    storage.reserve(NumberOfKids());

    for (int i = 0; i < Config.workers; ++i)
        storage.emplace_back("squid", storage.size() + 1);

    // add Kid records for all disk processes
    for (int i = 0; i < Config.cacheSwap.n_strands; ++i)
        storage.emplace_back("squid-disk", storage.size() + 1);

    // if coordination is needed, add a Kid record for Coordinator
    if (storage.size() > 1)
        storage.emplace_back("squid-coord", storage.size() + 1);

    Must(storage.size() == static_cast<size_t>(NumberOfKids()));
}

/// returns kid by pid
Kid* Kids::find(pid_t pid)
{
    assert(pid > 0);
    assert(count() > 0);

    for (size_t i = 0; i < storage.size(); ++i) {
        if (storage[i].getPid() == pid)
            return &storage[i];
    }
    return NULL;
}

/// returns the kid by index, useful for kids iteration
Kid& Kids::get(size_t i)
{
    assert(i < count());
    return storage[i];
}

/// whether all kids are hopeless
bool Kids::allHopeless() const
{
    for (size_t i = 0; i < storage.size(); ++i) {
        if (!storage[i].hopeless())
            return false;
    }
    return true;
}

void
Kids::forgetAllFailures()
{
    for (auto &kid: storage)
        kid.forgetFailures();
}

time_t
Kids::forgetOldFailures()
{
    time_t nextCheckDelay = 0;
    for (auto &kid: storage) {
        if (!kid.hopeless())
            continue;

        const auto deathDuration = kid.deathDuration(); // protect from time changes
        if (Config.hopelessKidRevivalDelay <= deathDuration) {
            kid.forgetFailures(); // this kid will be revived now
            continue;
        }

        const auto remainingDeathTime = Config.hopelessKidRevivalDelay - deathDuration;
        assert(remainingDeathTime > 0);
        if (remainingDeathTime < nextCheckDelay || !nextCheckDelay)
            nextCheckDelay = remainingDeathTime;
    }
    return nextCheckDelay; // still zero if there were no still-hopeless kids
}

/// whether all kids called exited happy
bool Kids::allExitedHappy() const
{
    for (size_t i = 0; i < storage.size(); ++i) {
        if (!storage[i].exitedHappy())
            return false;
    }
    return true;
}

/// whether some kids died from a given signal
bool Kids::someSignaled(const int sgnl) const
{
    for (size_t i = 0; i < storage.size(); ++i) {
        if (storage[i].signaled(sgnl))
            return true;
    }
    return false;
}

/// whether some kids are running
bool Kids::someRunning() const
{
    for (size_t i = 0; i < storage.size(); ++i) {
        if (storage[i].running())
            return true;
    }
    return false;
}

/// whether some kids should be restarted by master
bool Kids::shouldRestartSome() const
{
    for (size_t i = 0; i < storage.size(); ++i) {
        if (storage[i].shouldRestart())
            return true;
    }
    return false;
}

/// returns the number of kids
size_t Kids::count() const
{
    return storage.size();
}

