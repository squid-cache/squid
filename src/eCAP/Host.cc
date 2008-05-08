#include "squid.h"
#include <libecap/adapter/service.h>
#include "TextException.h"
#include "eCAP/ServiceRep.h"
#include "eCAP/Host.h"


std::string
Ecap::Host::uri() const
{
    return "ecap://squid-cache.org/ecap/hosts/squid";
}

void
Ecap::Host::describe(std::ostream &os) const
{
    os << PACKAGE_NAME << " v" << PACKAGE_VERSION;
}

void
Ecap::Host::noteService(const libecap::weak_ptr<libecap::adapter::Service> &weak)
{
    // Many ecap_service lines may use the same service URI. Find each 
    // matching service rep, make sure it is an eCAP rep,
	// and update it with the actual eCAP service.
    int found = 0;

	libecap::shared_ptr<libecap::adapter::Service> shared(weak);
    typedef Adaptation::Services::iterator SI;
    for (SI i = Adaptation::AllServices().begin(); i != Adaptation::AllServices().end(); ++i) {
        if ((*i)->cfg().uri == shared->uri().c_str()) {
            ServiceRep *rep = dynamic_cast<ServiceRep*>(i->getRaw());
			Must(rep);
			rep->noteService(shared);
            ++found;
		}
	}

	debugs(93,5, "Found " << found << " ecap_service configs for " <<
        shared->uri());
    if (!found) {
		debugs(93,1, "Warning: ignoring loaded eCAP module service without " <<
            "a matching ecap_service configuration: " << shared->uri());
	}
}

static int
SquidLogLevel(libecap::LogVerbosity lv)
{
	if (lv.critical())
		return DBG_CRITICAL; // is it a good idea to ignore other flags?

	if (lv.large())
		return DBG_DATA; // is it a good idea to ignore other flags?

	if (lv.application())
		return DBG_DATA; // is it a good idea to ignore other flags?

	return 2 + 2*lv.debugging() + 3*lv.operation() + 2*lv.xaction();
}

std::ostream *
Ecap::Host::openDebug(libecap::LogVerbosity lv)
{
    const int squidLevel = SquidLogLevel(lv);
    const int squidSection = 93; // XXX: this should be a global constant
    // XXX: Debug.h should provide this to us
	if ((Debug::level = squidLevel) <= Debug::Levels[squidSection])
		return &Debug::getDebugOut();
	else
		return NULL;
}

void
Ecap::Host::closeDebug(std::ostream *debug)
{
	if (debug)
		Debug::finishDebug();
}
