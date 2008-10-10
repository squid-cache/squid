#include "squid.h"

#include "ConfigParser.h"
#include "Array.h"      // really Vector
#include "adaptation/Config.h"
#include "adaptation/AccessRule.h"
#include "adaptation/Service.h"
#include "adaptation/ServiceGroups.h"


Adaptation::ServiceGroup::ServiceGroup(const String &aKind): kind(aKind)
{
}

Adaptation::ServiceGroup::~ServiceGroup()
{
}

void
Adaptation::ServiceGroup::parse()
{
    ConfigParser::ParseString(&id);

    wordlist *names = NULL;
    ConfigParser::ParseWordList(&names);
    for (wordlist *i = names; i; i = i->next)
        services.push_back(i->key);
    wordlistDestroy(&names);
}

void
Adaptation::ServiceGroup::finalize()
{
    for (iterator i = services.begin(); i != services.end(); ++i) {
        const String &id = *i;
        // TODO: fail on failures
        if (!FindService(id))
            debugs(93,0, "ERROR: Unknown adaptation name: " << id);
    }
    debugs(93,7, HERE << "finalized " << kind << ": " << id);
}

/* ServiceSet */

Adaptation::ServiceSet::ServiceSet(): ServiceGroup("adaptation set")
{
}

Adaptation::ServiceGroup::Loop Adaptation::ServiceSet::initialServices()
{
    return Loop(services.begin(), services.end());
}

#if FUTURE_OPTIMIZATION
void
Adaptation::ServiceSet::finalize()
{
    ServiceGroup::finalize();

    for (wordlist *iter = service_names; iter; iter = iter->next) {
        ServicePointer match = Config::FindService(iter->id);
        if (match != NULL)
            services += match;
    }
}
#endif


/* SingleService */

Adaptation::SingleService::SingleService(const String &aServiceId):
        ServiceGroup("single-service group")
{
    id = aServiceId;
    services.push_back(aServiceId);
}

Adaptation::ServiceGroup::Loop
Adaptation::SingleService::initialServices()
{
    return Loop(services.begin(), services.end()); // there should be only one
}


/* globals */

Adaptation::Groups &
Adaptation::AllGroups()
{
    static Groups TheGroups;
    return TheGroups;
}

Adaptation::ServiceGroup *
Adaptation::FindGroup(const ServiceGroup::Id &id)
{
    typedef Groups::iterator GI;
    for (GI i = AllGroups().begin(); i != AllGroups().end(); ++i) {
        if ((*i)->id == id)
            return *i;
    }

    return NULL;
}
