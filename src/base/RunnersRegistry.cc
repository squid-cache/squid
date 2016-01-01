/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "base/RunnersRegistry.h"
#include <set>

/// a collection of unique runners, in no particular order
typedef std::set<RegisteredRunner*> Runners;
/// all known runners
static Runners *TheRunners = NULL;

/// safely returns registered runners, initializing structures as needed
static Runners &
GetRunners()
{
    if (!TheRunners)
        TheRunners = new Runners;
    return *TheRunners;
}

int
RegisterRunner(RegisteredRunner *rr)
{
    Runners &runners = GetRunners();
    runners.insert(rr);
    return runners.size();
}

int
DeregisterRunner(RegisteredRunner *rr)
{
    Runners &runners = GetRunners();
    runners.erase(rr);
    return runners.size();
}

void
RunRegistered(const RegisteredRunner::Method &m)
{
    Runners &runners = GetRunners();
    typedef Runners::iterator RRI;
    for (RRI i = runners.begin(); i != runners.end(); ++i)
        ((*i)->*m)();

    if (m == &RegisteredRunner::finishShutdown) {
        delete TheRunners;
        TheRunners = NULL;
    }
}

bool
UseThisStatic(const void *)
{
    return true;
}

