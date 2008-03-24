#ifndef SQUID_ADAPTATION__SERVICE_H
#define SQUID_ADAPTATION__SERVICE_H

#include "SquidString.h"
#include "adaptation/Elements.h"

namespace Adaptation {

// manages adaptation service configuration in squid.conf
// specific adaptation mechanisms extend this class
class Service
{
public:
    Service();
    virtual ~Service();

    const char *methodStr() const;
    const char *vectPointStr() const;

public:
    String key;    // service name in the configuration file
    String uri;    // service URI

    // service URI components
    String host;
    String resource;
    int port;

    Method method;   // what is being adapted (REQMOD vs RESPMOD)
    VectPoint point; // where the adaptation happens (pre- or post-cache)
    bool bypass;

protected:
    bool configure();
    Method parseMethod(const char *str) const;
    VectPoint parseVectPoint(const char *service) const;
};

} // namespace Adaptation

#endif /* SQUID_ADAPTATION__SERVICE_H */
