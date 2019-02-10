/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 93    Adaptation */

#include "squid.h"
#include "adaptation/Service.h"
#include "adaptation/ServiceFilter.h"
#include "HttpRequest.h"

Adaptation::Service::Service(const ServiceConfigPointer &aConfig): theConfig(aConfig)
{
    Must(theConfig != NULL);
    debugs(93,3, HERE << "creating adaptation service " << cfg().key);
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
        return wantsUrl(filter.request->url.path());
    }

    // The service is down and is either not bypassable or not probed due
    // to the bypass && broken() test above. Thus, we want to use it!
    return true;
}

Adaptation::Services &
Adaptation::AllServices()
{
    static Services *TheServices = new Services;
    return *TheServices;
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
    while (!AllServices().empty()) {
        AllServices().back()->detach();
        AllServices().pop_back();
    }
}

