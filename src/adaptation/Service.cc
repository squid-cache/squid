/*
 * DEBUG: section XXX
 */

#include "squid.h"
#include "adaptation/Service.h"

Adaptation::Service::Service(const ServiceConfig &aConfig): theConfig(aConfig)
{}

Adaptation::Service::~Service()
{}

bool
Adaptation::Service::finalize()
{
    return true;
}
