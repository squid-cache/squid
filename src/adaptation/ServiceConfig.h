#ifndef SQUID_ADAPTATION__SERVICE_CONFIG_H
#define SQUID_ADAPTATION__SERVICE_CONFIG_H

#include "SquidString.h"
#include "RefCount.h"
#include "adaptation/Elements.h"

namespace Adaptation
{

// manages adaptation service configuration in squid.conf
class ServiceConfig
{
public:
    ServiceConfig();

    const char *methodStr() const;
    const char *vectPointStr() const;

    bool parse();

public:
    String key;    // service_configConfig name in the configuration file
    String uri;    // service_configConfig URI

    // service_configConfig URI components
    String protocol;
    String host;
    String resource;
    int port;

    Method method;   // what is being adapted (REQMOD vs RESPMOD)
    VectPoint point; // where the adaptation happens (pre- or post-cache)
    bool bypass;

protected:
    Method parseMethod(const char *buf) const;
    VectPoint parseVectPoint(const char *buf) const;
};

} // namespace Adaptation

#endif /* SQUID_ADAPTATION__SERVICE_CONFIG_H */
