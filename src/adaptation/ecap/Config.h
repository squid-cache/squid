/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
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
    virtual bool grokExtension(const char *name, const char *value);

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
    ~Config();

    virtual bool finalize();

protected:
    virtual Adaptation::ServiceConfig *newServiceConfig() const;

private:
    Config(const Config &); // not implemented
    Config &operator =(const Config &); // not implemented

    virtual Adaptation::ServicePointer createService(const ServiceConfigPointer &cfg);
};

extern Config TheConfig;

} // namespace Ecap
} // namespace Adaptation

#endif /* SQUID_ECAP_CONFIG_H */

