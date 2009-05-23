#include "squid.h"
#include <libecap/adapter/service.h>
#include "TextException.h"
#include "adaptation/ecap/ServiceRep.h"
#include "adaptation/ecap/XactionRep.h"

Adaptation::Ecap::ServiceRep::ServiceRep(const Adaptation::ServiceConfig &cfg):
        /*AsyncJob("Adaptation::Ecap::ServiceRep"),*/ Adaptation::Service(cfg)
{
}

Adaptation::Ecap::ServiceRep::~ServiceRep()
{
}

void Adaptation::Ecap::ServiceRep::noteService(const AdapterService &s)
{
    Must(s != NULL);
    theService = s;
    debugs(93,7, HERE << "matched loaded and configured eCAP services: " <<
           s->uri() << ' ' << cfg().key << "\n");
}

void Adaptation::Ecap::ServiceRep::invalidate()
{
    theService->retire();
    theService.reset();
}

void Adaptation::Ecap::ServiceRep::noteFailure()
{
    assert(false); // XXX: should this be ICAP-specific?
}

void
Adaptation::Ecap::ServiceRep::finalize()
{
    Adaptation::Service::finalize();
    if (theService) {
        debugs(93,3, HERE << "starting eCAP service: " << theService->uri());
        theService->start();
    } else {
        debugs(93,1, "Warning: configured ecap_service was not loaded: " <<
               cfg().uri);
    }
}

bool Adaptation::Ecap::ServiceRep::probed() const
{
    return true; // we "probe" the adapter in finalize().
}

bool Adaptation::Ecap::ServiceRep::up() const
{
    return theService != NULL;
}

bool Adaptation::Ecap::ServiceRep::wantsUrl(const String &urlPath) const
{
    Must(up());
    return theService->wantsUrl(urlPath.termedBuf());
}

Adaptation::Initiate *
Adaptation::Ecap::ServiceRep::makeXactLauncher(Adaptation::Initiator *initiator,
        HttpMsg *virgin, HttpRequest *cause)
{
    Must(up());
    XactionRep *rep = new XactionRep(initiator, virgin, cause, Pointer(this));
    XactionRep::AdapterXaction x(theService->makeXaction(rep));
    rep->master(x);
    return rep;
}

// returns a temporary string depicting service status, for debugging
const char *Adaptation::Ecap::ServiceRep::status() const
{
    assert(false); // move generic stuff from ICAP to Adaptation
    // add theService->status()?
    return NULL;
}
