
/*
 * $Id$
 */

#include "squid.h"

#include <libecap/common/registry.h>
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
    libecap::shared_ptr<Adaptation::Ecap::Host> host(new Adaptation::Ecap::Host);
    libecap::RegisterHost(host);
}

Adaptation::ServicePointer
Adaptation::Ecap::Config::createService(const Adaptation::ServiceConfig &cfg)
{
    Adaptation::ServicePointer s = new Adaptation::Ecap::ServiceRep(cfg);
    return s.getRaw();
}

