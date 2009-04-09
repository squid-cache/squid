
/*
 * $Id$
 */

#ifndef SQUID_ECAP_HOST_H
#define SQUID_ECAP_HOST_H

#include <libecap/host/host.h>

namespace Adaptation
{
namespace Ecap {

// Squid wrapper, providing host application functionality to eCAP services.
class Host : public libecap::host::Host
{
public:
    Host();

    // About
    virtual std::string uri() const; // unique across all vendors
    virtual void describe(std::ostream &os) const; // free-format info

    // Service management
    virtual void noteService(const libecap::weak_ptr<libecap::adapter::Service> &s);

    // Logging
    virtual std::ostream *openDebug(libecap::LogVerbosity lv);
    virtual void closeDebug(std::ostream *debug);
};

extern const libecap::Name protocolInternal;
extern const libecap::Name protocolCacheObj;
extern const libecap::Name protocolIcp;
#if USE_HTCP
extern const libecap::Name protocolHtcp;
#endif

} // namespace Ecap
} // namespace Adaptation

#endif /* SQUID_ECAP_HOST_H */
