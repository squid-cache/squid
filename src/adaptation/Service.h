#ifndef SQUID_ADAPTATION__SERVICE_H
#define SQUID_ADAPTATION__SERVICE_H

#include "SquidString.h"
#include "RefCount.h"
#include "adaptation/forward.h"
#include "adaptation/Elements.h"
#include "adaptation/ServiceConfig.h"

// TODO: Move src/ICAP/ICAPServiceRep.h API comments here and update them

class HttpMsg;
class HttpRequest;

namespace Adaptation
{

// manages adaptation service configuration in squid.conf
// specific adaptation mechanisms extend this class
class Service: public RefCountable
{
public:
    typedef RefCount<Service> Pointer;
    typedef String Id;

public:
    Service(const ServiceConfig &aConfig);
    virtual ~Service();

    // call when the service is no longer needed or valid
    virtual void invalidate() = 0;

    virtual bool probed() const = 0; // see comments above
    virtual bool broken() const;
    virtual bool up() const = 0; // see comments above

    virtual Initiate *makeXactLauncher(Initiator *, HttpMsg *virginHeader, HttpRequest *virginCause) = 0;

    typedef void Callback(void *data, Pointer &service);
    void callWhenReady(Callback *cb, void *data);

    bool wants(const ServiceFilter &filter) const;

    // the methods below can only be called on an up() service
    virtual bool wantsUrl(const String &urlPath) const = 0;

    // called by transactions to report service failure
    virtual void noteFailure() = 0;

    const ServiceConfig &cfg() const { return theConfig; }

    virtual void finalize(); // called after creation

protected:
    ServiceConfig &writeableCfg() { return theConfig; }

private:
    ServiceConfig theConfig;
};

typedef Service::Pointer ServicePointer;

typedef Vector<Adaptation::ServicePointer> Services;
extern Services &AllServices();
extern ServicePointer FindService(const Service::Id &key);

} // namespace Adaptation

#endif /* SQUID_ADAPTATION__SERVICE_H */
