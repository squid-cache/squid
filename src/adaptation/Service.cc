/*
 * DEBUG: section XXX
 */

#include "squid.h"
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
