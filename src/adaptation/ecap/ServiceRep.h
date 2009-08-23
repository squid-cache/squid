
/*
 * $Id$
 */

#ifndef SQUID_ECAP_SERVICE_REP_H
#define SQUID_ECAP_SERVICE_REP_H

#include "adaptation/Service.h"
#include "adaptation/forward.h"
#include <libecap/common/forward.h>
#include <libecap/common/memory.h>

namespace Adaptation
{
namespace Ecap
{

/* The eCAP service representative maintains information about a single eCAP
   service that Squid communicates with. One eCAP module may register many
   eCAP services. */

class ServiceRep : public Adaptation::Service
{
public:
    ServiceRep(const Adaptation::ServiceConfig &config);
    virtual ~ServiceRep();

    typedef libecap::shared_ptr<libecap::adapter::Service> AdapterService;
    void noteService(const AdapterService &s);

    virtual void finalize();

    // call when the service is no longer needed or valid
    virtual void invalidate();

    virtual bool probed() const;
    virtual bool up() const;

    Adaptation::Initiate *makeXactLauncher(Adaptation::Initiator *, HttpMsg *virginHeader, HttpRequest *virginCause);

    // the methods below can only be called on an up() service
    virtual bool wantsUrl(const String &urlPath) const;

    // called by transactions to report service failure
    virtual void noteFailure();

    virtual const char *status() const;

private:
    AdapterService theService; // the actual adaptation service we represent
};

} // namespace Ecap
} // namespace Adaptation

#endif /* SQUID_ECAP_SERVICE_REP_H */
