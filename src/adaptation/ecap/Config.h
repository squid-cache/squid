/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 93    eCAP Interface */

#ifndef SQUID_ECAP_CONFIG_H
#define SQUID_ECAP_CONFIG_H

#include "adaptation/Config.h"
#include "adaptation/ServiceConfig.h"
#include <list>
#include <utility>

namespace Adaptation
{
namespace Ecap
{

/// eCAP service configuration
class ServiceConfig: public Adaptation::ServiceConfig
{
public:
    // Adaptation::ServiceConfig API
    bool grokExtension(const char *name, const char *value) override;

public:
    typedef std::pair<std::string, std::string> Extension; // name=value in cfg
    typedef std::list<Extension> Extensions;
    Extensions extensions;
};

/// General eCAP configuration
class Config: public Adaptation::Config
{

public:
    Config();
    ~Config() override;

    bool finalize() override;

protected:
    Adaptation::ServiceConfig *newServiceConfig() const override;

private:
    Config(const Config &); // not implemented
    Config &operator =(const Config &); // not implemented

    Adaptation::ServicePointer createService(const ServiceConfigPointer &cfg) override;
};

extern Config TheConfig;

} // namespace Ecap
} // namespace Adaptation

#endif /* SQUID_ECAP_CONFIG_H */

