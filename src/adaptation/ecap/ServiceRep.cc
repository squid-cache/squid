/*
 * DEBUG: section 93    eCAP Interface
 */
#include "squid.h"
#include "Debug.h"
#include <list>
#include <libecap/adapter/service.h>
#include <libecap/common/options.h>
#include <libecap/common/name.h>
#include <libecap/common/named_values.h>
#include "adaptation/ecap/Config.h"
#include "adaptation/ecap/Host.h"
#include "adaptation/ecap/ServiceRep.h"
#include "adaptation/ecap/XactionRep.h"
#include "base/TextException.h"

// configured eCAP service wrappers
static std::list<Adaptation::Ecap::ServiceRep::AdapterService> TheServices;

namespace Adaptation
{
namespace Ecap
{

/// wraps Adaptation::Ecap::ServiceConfig to allow eCAP visitors
class ConfigRep: public libecap::Options
{
public:
    typedef Adaptation::Ecap::ServiceConfig Master;
    typedef libecap::Name Name;
    typedef libecap::Area Area;

    ConfigRep(const Master &aMaster);

    // libecap::Options API
    virtual const libecap::Area option(const libecap::Name &name) const;
    virtual void visitEachOption(libecap::NamedValueVisitor &visitor) const;

    const Master &master; ///< the configuration being wrapped
};

} // namespace Ecap
} // namespace Adaptation

Adaptation::Ecap::ConfigRep::ConfigRep(const Master &aMaster): master(aMaster)
{
}

const libecap::Area
Adaptation::Ecap::ConfigRep::option(const libecap::Name &name) const
{
    // we may supply the params we know about, but only when names have host ID
    if (name == metaBypassable)
        return Area(master.bypass ? "1" : "0", 1);

    // TODO: We could build a by-name index, but is it worth it? Good adapters
    // should use visitEachOption() instead, to check for name typos/errors.
    typedef Master::Extensions::const_iterator MECI;
    for (MECI i = master.extensions.begin(); i != master.extensions.end(); ++i) {
        if (name == i->first)
            return Area(i->second.data(), i->second.size());
    }

    return Area();
}

void
Adaptation::Ecap::ConfigRep::visitEachOption(libecap::NamedValueVisitor &visitor) const
{
    // we may supply the params we know about too, but only if we set host ID
    visitor.visit(metaBypassable, Area(master.bypass ? "1" : "0", 1));

    // visit adapter-specific options (i.e., those not recognized by Squid)
    typedef Master::Extensions::const_iterator MECI;
    for (MECI i = master.extensions.begin(); i != master.extensions.end(); ++i)
        visitor.visit(Name(i->first), Area::FromTempString(i->second));
}

Adaptation::Ecap::ServiceRep::ServiceRep(const ServiceConfigPointer &cfg):
        /*AsyncJob("Adaptation::Ecap::ServiceRep"),*/ Adaptation::Service(cfg),
        isDetached(false)
{
}

Adaptation::Ecap::ServiceRep::~ServiceRep()
{
}

void Adaptation::Ecap::ServiceRep::noteFailure()
{
    assert(false); // XXX: should this be ICAP-specific?
}

void
Adaptation::Ecap::ServiceRep::finalize()
{
    Adaptation::Service::finalize();
    theService = FindAdapterService(cfg().uri);
    if (theService) {
        try {
            tryConfigureAndStart();
            Must(up());
        } catch (const std::exception &e) { // standardized exceptions
            if (!handleFinalizeFailure(e.what()))
                throw; // rethrow for upper layers to handle
        } catch (...) { // all other exceptions
            if (!handleFinalizeFailure("unrecognized exception"))
                throw; // rethrow for upper layers to handle
        }
        return; // success or handled exception
    } else {
        debugs(93,DBG_IMPORTANT, "WARNING: configured ecap_service was not loaded: " << cfg().uri);
    }
}

/// attempts to configure and start eCAP service; the caller handles exceptions
void
Adaptation::Ecap::ServiceRep::tryConfigureAndStart()
{
    debugs(93,2, HERE << "configuring eCAP service: " << theService->uri());
    const ConfigRep cfgRep(dynamic_cast<const ServiceConfig&>(cfg()));
    theService->configure(cfgRep);

    debugs(93,DBG_IMPORTANT, "Starting eCAP service: " << theService->uri());
    theService->start();
}

/// handles failures while configuring or starting an eCAP service;
/// returns false if the error must be propagated to higher levels
bool
Adaptation::Ecap::ServiceRep::handleFinalizeFailure(const char *error)
{
    const bool salvage = cfg().bypass;
    const int level = salvage ? DBG_IMPORTANT :DBG_CRITICAL;
    const char *kind = salvage ? "optional" : "essential";
    debugs(93, level, "ERROR: failed to start " << kind << " eCAP service: " <<
           cfg().uri << ":\n" << error);

    if (!salvage)
        return false; // we cannot handle the problem; the caller may escalate

    // make up() false, preventing new adaptation requests and enabling bypass
    theService.reset();
    debugs(93, level, "WARNING: " << kind << " eCAP service is " <<
           "down after initialization failure: " << cfg().uri);

    return true; // tell the caller to ignore the problem because we handled it
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
Adaptation::Ecap::ServiceRep::makeXactLauncher(HttpMsg *virgin,
        HttpRequest *cause)
{
    Must(up());
    XactionRep *rep = new XactionRep(virgin, cause, Pointer(this));
    XactionRep::AdapterXaction x(theService->makeXaction(rep));
    rep->master(x);
    return rep;
}

// returns a temporary string depicting service status, for debugging
const char *Adaptation::Ecap::ServiceRep::status() const
{
    // TODO: move generic stuff from eCAP and ICAP to Adaptation
    static MemBuf buf;

    buf.reset();
    buf.append("[", 1);

    if (up())
        buf.append("up", 2);
    else
        buf.append("down", 4);

    if (detached())
        buf.append(",detached", 9);

    buf.append("]", 1);
    buf.terminate();

    return buf.content();
}

void Adaptation::Ecap::ServiceRep::detach()
{
    isDetached = true;
}

bool Adaptation::Ecap::ServiceRep::detached() const
{
    return isDetached;
}

Adaptation::Ecap::ServiceRep::AdapterService
Adaptation::Ecap::FindAdapterService(const String& serviceUri)
{
    typedef std::list<ServiceRep::AdapterService>::const_iterator ASCI;
    for (ASCI s = TheServices.begin(); s != TheServices.end(); ++s) {
        Must(*s);
        if (serviceUri == (*s)->uri().c_str())
            return *s;
    }
    return ServiceRep::AdapterService();
}

void
Adaptation::Ecap::RegisterAdapterService(const Adaptation::Ecap::ServiceRep::AdapterService& adapterService)
{
    typedef std::list<ServiceRep::AdapterService>::iterator ASI;
    for (ASI s = TheServices.begin(); s != TheServices.end(); ++s) {
        Must(*s);
        if (adapterService->uri() == (*s)->uri()) {
            *s = adapterService;
            debugs(93, 3, "updated eCAP module service: " <<
                   adapterService->uri());
            return;
        }
    }
    TheServices.push_back(adapterService);
    debugs(93, 3, "registered eCAP module service: " << adapterService->uri());
}

void
Adaptation::Ecap::UnregisterAdapterService(const String& serviceUri)
{
    typedef std::list<ServiceRep::AdapterService>::iterator ASI;
    for (ASI s = TheServices.begin(); s != TheServices.end(); ++s) {
        if (serviceUri == (*s)->uri().c_str()) {
            TheServices.erase(s);
            debugs(93, 3, "unregistered eCAP module service: " << serviceUri);
            return;
        }
    }
    debugs(93, 3, "failed to unregister eCAP module service: " << serviceUri);
}

void
Adaptation::Ecap::CheckUnusedAdapterServices(const Adaptation::Services& cfgs)
{
    typedef std::list<ServiceRep::AdapterService>::const_iterator ASCI;
    for (ASCI loaded = TheServices.begin(); loaded != TheServices.end();
            ++loaded) {
        bool found = false;
        for (Services::const_iterator cfged = cfgs.begin();
                cfged != cfgs.end() && !found; ++cfged) {
            found = (*cfged)->cfg().uri == (*loaded)->uri().c_str();
        }
        if (!found)
            debugs(93, DBG_IMPORTANT, "Warning: loaded eCAP service has no matching " <<
                   "ecap_service config option: " << (*loaded)->uri());
    }
}
