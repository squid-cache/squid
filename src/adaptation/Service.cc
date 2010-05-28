/*
 * DEBUG: section 93    Adaptation
 */

#include "squid.h"
#include "HttpRequest.h"
#include "adaptation/ServiceFilter.h"
#include "adaptation/Service.h"

Adaptation::Service::Service(const ServiceConfig &aConfig): theConfig(aConfig)
{
    debugs(93,3, HERE << "creating adaptation service " << theConfig.key);
}

Adaptation::Service::~Service()
{}

void
Adaptation::Service::finalize()
{
}

bool Adaptation::Service::broken() const
{
    return probed() && !up();
}

bool
Adaptation::Service::wants(const ServiceFilter &filter) const
{
    if (cfg().method != filter.method)
        return false;

    if (cfg().point != filter.point)
        return false;

    // sending a message to a broken service is likely to cause errors
    if (cfg().bypass && broken())
        return false;

    if (up()) {
        // Sending a message to a service that does not want it is useless.
        // note that we cannot check wantsUrl for service that is not "up"
        // note that even essential services are skipped on unwanted URLs!
        return wantsUrl(filter.request->urlpath);
    }

    // The service is down and is either not bypassable or not probed due
    // to the bypass && broken() test above. Thus, we want to use it!
    return true;
}


Adaptation::Services &
Adaptation::AllServices()
{
    static Services TheServices;
    return TheServices;
}

Adaptation::ServicePointer
Adaptation::FindService(const Service::Id& key)
{
    typedef Services::iterator SI;
    for (SI i = AllServices().begin(); i != AllServices().end(); ++i) {
        if ((*i)->cfg().key == key)
            return *i;
    }
    return NULL;
}

void Adaptation::DetachServices()
{
    while (!AllServices().empty())
        AllServices().pop_back()->detach();
}
