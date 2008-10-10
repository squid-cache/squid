
/*
 * $Id$
 */

#include "squid.h"

#include <libecap/common/registry.h>
#include "eCAP/Host.h"
#include "eCAP/ServiceRep.h"
#include "eCAP/Config.h"

Ecap::Config Ecap::TheConfig;

Ecap::Config::Config()
{
}

Ecap::Config::~Config()
{
}

void
Ecap::Config::finalize()
{
    Adaptation::Config::finalize();
    libecap::shared_ptr<Ecap::Host> host(new Ecap::Host);
    libecap::RegisterHost(host);
}

Adaptation::ServicePointer
Ecap::Config::createService(const Adaptation::ServiceConfig &cfg)
{
    Adaptation::ServicePointer s = new Ecap::ServiceRep(cfg);
    return s.getRaw();
}

