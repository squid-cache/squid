/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 93    eCAP Interface */

#include "squid.h"
#include "adaptation/ecap/Config.h"
#include "adaptation/ecap/Host.h"
#include "adaptation/ecap/ServiceRep.h"

Adaptation::Ecap::Config Adaptation::Ecap::TheConfig;

Adaptation::Ecap::Config::Config()
{
}

Adaptation::Ecap::Config::~Config()
{
}

bool
Adaptation::Ecap::Config::finalize()
{
    if (!Adaptation::Config::finalize())
        return false;
    Host::Register();
    CheckUnusedAdapterServices(AllServices());
    return true;
}

Adaptation::ServiceConfig *
Adaptation::Ecap::Config::newServiceConfig() const
{
    return new ServiceConfig();
}

Adaptation::ServicePointer
Adaptation::Ecap::Config::createService(const ServiceConfigPointer &cfg)
{
    return new Adaptation::Ecap::ServiceRep(cfg);
}

/* ServiceConfig */

bool
Adaptation::Ecap::ServiceConfig::grokExtension(const char *name, const char *value)
{
    extensions.push_back(std::make_pair(name, value));
    return true;
}

