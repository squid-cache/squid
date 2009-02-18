#include "squid.h"
#include <libecap/adapter/service.h>
#include "TextException.h"
#include "eCAP/ServiceRep.h"
#include "eCAP/XactionRep.h"

Ecap::ServiceRep::ServiceRep(const Adaptation::ServiceConfig &cfg):
        /*AsyncJob("Ecap::ServiceRep"),*/ Adaptation::Service(cfg)
{
}

Ecap::ServiceRep::~ServiceRep()
{
}

void Ecap::ServiceRep::noteService(const AdapterService &s)
{
    Must(s != NULL);
    theService = s;
    debugs(93,7, "Matched loaded and configured eCAP services: " <<
           s->uri() << ' ' << cfg().key << "\n");
}

void Ecap::ServiceRep::invalidate()
{
    theService->retire();
    theService.reset();
}

void Ecap::ServiceRep::noteFailure()
{
    assert(false); // XXX: should this be ICAP-specific?
}

void
Ecap::ServiceRep::finalize()
{
    Adaptation::Service::finalize();
    if (!theService) {
        debugs(93,1, "Warning: configured ecap_service was not loaded: " <<
               cfg().uri);
    }
}

bool Ecap::ServiceRep::probed() const
{
    return true; // we "probe" the adapter in finalize().
}

bool Ecap::ServiceRep::up() const
{
    return theService != NULL;
}

bool Ecap::ServiceRep::wantsUrl(const String &urlPath) const
{
    Must(up());
    return theService->wantsUrl(urlPath.termedBuf());
}

Adaptation::Initiate *
Ecap::ServiceRep::makeXactLauncher(Adaptation::Initiator *initiator,
                                   HttpMsg *virgin, HttpRequest *cause)
{
    Must(up());
    XactionRep *rep = new XactionRep(initiator, virgin, cause, Pointer(this));
    XactionRep::AdapterXaction x(theService->makeXaction(rep));
    rep->master(x);
    return rep;
}

// returns a temporary string depicting service status, for debugging
const char *Ecap::ServiceRep::status() const
{
    assert(false); // move generic stuff from ICAP to Adaptation
    // add theService->status()?
    return NULL;
}
