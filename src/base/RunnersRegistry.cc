/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "base/RunnersRegistry.h"
#include "base/TextException.h"
#include "Debug.h"
#include <set>

/// a collection of unique runners, in no particular order
typedef std::set<RegisteredRunner*> Runners;
/// all known runners
static Runners *TheRunners = NULL;
/// used to avoid re-creating deleted TheRunners after shutdown finished.
static bool RunnersGone = false;

/// creates the registered runners container if needed
/// \return either registered runners (if they should exist) or nil (otherwise)
static inline Runners *
FindRunners()
{
    if (!TheRunners && !RunnersGone)
        TheRunners = new Runners;
    return TheRunners;
}

static inline void
GetRidOfRunner(RegisteredRunner *rr)
{
    if (!dynamic_cast<IndependentRunner*>(rr))
        delete rr;
    // else ignore; IndependentRunner
}

static inline void
RegisterRunner_(RegisteredRunner *rr)
{
    Runners *runners = FindRunners();
    Must(runners);
    runners->insert(rr);
}

bool
RegisterRunner(RegisteredRunner *rr)
{
    Must(!dynamic_cast<IndependentRunner*>(rr));

    if (FindRunners()) {
        RegisterRunner_(rr);
        return true;
    }

    // past finishShutdown
    GetRidOfRunner(rr);
    return false;
}

void
RunRegistered(const RegisteredRunner::Method &event)
{
    if (Runners *runners = FindRunners()) {
        // Many things may happen during the loop below. We copy to withstand
        // runner removal/addition and avoid surprises due to registrations from
        // parent constructors (with a half-baked "this"!). This copy also
        // simplifies overall RR logic as it guarantees that registering a
        // runner during event X loop does not execute runner::X().
        Runners oldRunners(*runners);
        for (auto runner: oldRunners) {
            if (runners->find(runner) != runners->end()) // still registered
                (runner->*event)();
        }
    }

    if (event != &RegisteredRunner::finishShutdown)
        return;

    // this is the last event; delete registry-dependent runners (and only them)
    if (Runners *runners = FindRunners()) {
        RunnersGone = true;
        TheRunners = nullptr;
        // from now on, no runners can be registered or unregistered
        for (auto runner: *runners)
            GetRidOfRunner(runner); // leaves a dangling pointer in runners
        delete runners;
    }
}

/* IndependentRunner */

void
IndependentRunner::unregisterRunner()
{
    if (Runners *runners = FindRunners())
        runners->erase(this);
    // else it is too late, finishShutdown() has been called
}

void
IndependentRunner::registerRunner()
{
    if (FindRunners())
        RegisterRunner_(this);
    // else do nothing past finishShutdown
}

bool
UseThisStatic(const void *)
{
    return true;
}

