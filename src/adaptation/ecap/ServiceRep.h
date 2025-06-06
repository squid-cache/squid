/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 93    eCAP Interface */

#ifndef SQUID_SRC_ADAPTATION_ECAP_SERVICEREP_H
#define SQUID_SRC_ADAPTATION_ECAP_SERVICEREP_H

#include "adaptation/forward.h"
#include "adaptation/Service.h"

#if HAVE_LIBECAP_COMMON_FORWARD_H
#include <libecap/common/forward.h>
#endif
#if HAVE_LIBECAP_COMMON_MEMORY_H
#include <libecap/common/memory.h>
#endif

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
    explicit ServiceRep(const ServiceConfigPointer &aConfig);
    ~ServiceRep() override;

    typedef libecap::shared_ptr<libecap::adapter::Service> AdapterService;

    /* Adaptation::Service API */
    void finalize() override;
    bool probed() const override;
    bool up() const override;
    Adaptation::Initiate *makeXactLauncher(Http::Message *virginHeader, HttpRequest *virginCause, AccessLogEntry::Pointer &alp) override;
    bool wantsUrl(const SBuf &urlPath) const override;
    void noteFailure() override;
    virtual const char *status() const;
    void detach() override;
    bool detached() const override;

protected:
    void tryConfigureAndStart();
    bool handleFinalizeFailure(const char *error);

private:
    AdapterService theService; // the actual adaptation service we represent
    bool           isDetached;
};

/// register loaded eCAP module service
void RegisterAdapterService(const ServiceRep::AdapterService& adapterService);
/// unregister loaded eCAP module service by service uri
void UnregisterAdapterService(const String& serviceUri);

/// returns loaded eCAP module service by service uri
ServiceRep::AdapterService FindAdapterService(const String& serviceUri);

/// check for loaded eCAP services without matching ecap_service in squid.conf
void CheckUnusedAdapterServices(const Services& services);
} // namespace Ecap
} // namespace Adaptation

#endif /* SQUID_SRC_ADAPTATION_ECAP_SERVICEREP_H */

