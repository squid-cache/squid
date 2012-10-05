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
    explicit Service(const ServiceConfigPointer &aConfig);
    virtual ~Service();

    virtual bool probed() const = 0; // see comments above
    virtual bool broken() const;
    virtual bool up() const = 0; // see comments above

    virtual Initiate *makeXactLauncher(HttpMsg *virginHeader, HttpRequest *virginCause) = 0;

    bool wants(const ServiceFilter &filter) const;

    // the methods below can only be called on an up() service
    virtual bool wantsUrl(const String &urlPath) const = 0;

    // called by transactions to report service failure
    virtual void noteFailure() = 0;

    const ServiceConfig &cfg() const { return *theConfig; }

    virtual void finalize(); // called after creation

    /// called when removed from the config; the service will be
    /// auto-destroyed when the last refcounting user leaves
    virtual void detach() = 0;
    /// whether detached() was called
    virtual bool detached() const = 0;

protected:
    ServiceConfig &writeableCfg() { return *theConfig; }

private:
    ServiceConfigPointer theConfig;
};

typedef Service::Pointer ServicePointer;

typedef Vector<Adaptation::ServicePointer> Services;
Services &AllServices();
ServicePointer FindService(const Service::Id &key);

/// detach all adaptation services from current configuration
void DetachServices();

} // namespace Adaptation

#endif /* SQUID_ADAPTATION__SERVICE_H */
