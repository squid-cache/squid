/*
 * $Id$
 * DEBUG: section 93    eCAP Interface
 */
#include "squid.h"

#include "adaptation/ecap/Host.h"
#include "adaptation/ecap/ServiceRep.h"
#include "adaptation/ecap/Config.h"

Adaptation::Ecap::Config Adaptation::Ecap::TheConfig;

Adaptation::Ecap::Config::Config()
{
}

Adaptation::Ecap::Config::~Config()
{
}

void
Adaptation::Ecap::Config::finalize()
{
    Adaptation::Config::finalize();
    Host::Register();
    CheckUnusedAdapterServices(AllServices());
}

Adaptation::ServicePointer
Adaptation::Ecap::Config::createService(const Adaptation::ServiceConfig &cfg)
{
    Adaptation::ServicePointer s = new Adaptation::Ecap::ServiceRep(cfg);
    return s.getRaw();
}

