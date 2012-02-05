#include "squid.h"
#include "base/RunnersRegistry.h"
#include <list>
#include <map>

typedef std::list<RegisteredRunner*> Runners;
typedef std::map<RunnerRegistry, Runners*> Registries;

/// all known registries
static Registries *TheRegistries = NULL;

/// returns the requested runners list, initializing structures as needed
static Runners &
GetRunners(const RunnerRegistry &registryId)
{
    if (!TheRegistries)
        TheRegistries = new Registries;

    if (TheRegistries->find(registryId) == TheRegistries->end())
        (*TheRegistries)[registryId] = new Runners;

    return *(*TheRegistries)[registryId];
}

int
RegisterRunner(const RunnerRegistry &registryId, RegisteredRunner *rr)
{
    Runners &runners = GetRunners(registryId);
    runners.push_back(rr);
    return runners.size();
}

int
ActivateRegistered(const RunnerRegistry &registryId)
{
    Runners &runners = GetRunners(registryId);
    typedef Runners::iterator RRI;
    for (RRI i = runners.begin(); i != runners.end(); ++i)
        (*i)->run(registryId);
    return runners.size();
}

void
DeactivateRegistered(const RunnerRegistry &registryId)
{
    Runners &runners = GetRunners(registryId);
    while (!runners.empty()) {
        delete runners.back();
        runners.pop_back();
    }
}

bool
UseThisStatic(const void *)
{
    return true;
}
