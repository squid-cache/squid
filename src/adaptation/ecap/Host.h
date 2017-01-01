/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 93    eCAP Interface */

#ifndef SQUID_ECAP_HOST_H
#define SQUID_ECAP_HOST_H

#include <libecap/host/host.h>

namespace Adaptation
{
namespace Ecap
{

// Squid wrapper, providing host application functionality to eCAP services.
class Host : public libecap::host::Host
{
public:
    /* libecap::host::Host API */
    virtual std::string uri() const; // unique across all vendors
    virtual void describe(std::ostream &os) const; // free-format info
    virtual void noteVersionedService(const char *libEcapVersion, const libecap::weak_ptr<libecap::adapter::Service> &s);
    virtual std::ostream *openDebug(libecap::LogVerbosity lv);
    virtual void closeDebug(std::ostream *debug);
    typedef libecap::shared_ptr<libecap::Message> MessagePtr;
    virtual MessagePtr newRequest() const;
    virtual MessagePtr newResponse() const;

    static void Register(); ///< register adaptation host

private:
    Host();
    Host (const Host&); ///< not implemented
    Host& operator= (const Host&); ///< not implemented
};

extern const libecap::Name protocolInternal;
extern const libecap::Name protocolCacheObj;
extern const libecap::Name protocolIcp;
extern const libecap::Name protocolIcy;
extern const libecap::Name protocolUnknown;
#if USE_HTCP
extern const libecap::Name protocolHtcp;
#endif
extern const libecap::Name metaBypassable; ///< an ecap_service parameter

} // namespace Ecap
} // namespace Adaptation

#endif /* SQUID_ECAP_HOST_H */

