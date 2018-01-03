/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 93    eCAP Interface */

#include "squid.h"
#include <libecap/adapter/service.h>
#include <libecap/common/names.h>
#include <libecap/common/registry.h>
#include "adaptation/ecap/Host.h"
#include "adaptation/ecap/MessageRep.h"
#include "adaptation/ecap/ServiceRep.h"
#include "base/TextException.h"
#include "HttpReply.h"
#include "HttpRequest.h"
#include "MasterXaction.h"

const libecap::Name Adaptation::Ecap::protocolInternal("internal", libecap::Name::NextId());
const libecap::Name Adaptation::Ecap::protocolCacheObj("cache_object", libecap::Name::NextId());
const libecap::Name Adaptation::Ecap::protocolIcp("ICP", libecap::Name::NextId());
#if USE_HTCP
const libecap::Name Adaptation::Ecap::protocolHtcp("Htcp", libecap::Name::NextId());
#endif
const libecap::Name Adaptation::Ecap::protocolIcy("ICY", libecap::Name::NextId());
const libecap::Name Adaptation::Ecap::protocolUnknown("_unknown_", libecap::Name::NextId());

const libecap::Name Adaptation::Ecap::metaBypassable("bypassable", libecap::Name::NextId());

/// the host application (i.e., Squid) wrapper registered with libecap
static libecap::shared_ptr<Adaptation::Ecap::Host> TheHost;

Adaptation::Ecap::Host::Host()
{
    // assign our host-specific IDs to well-known names
    // this code can run only once

    libecap::headerTransferEncoding.assignHostId(Http::HdrType::TRANSFER_ENCODING);
    libecap::headerReferer.assignHostId(Http::HdrType::REFERER);
    libecap::headerContentLength.assignHostId(Http::HdrType::CONTENT_LENGTH);
    libecap::headerVia.assignHostId(Http::HdrType::VIA);
    // TODO: libecap::headerXClientIp.assignHostId(Http::HdrType::X_CLIENT_IP);
    // TODO: libecap::headerXServerIp.assignHostId(Http::HdrType::X_SERVER_IP);

    libecap::protocolHttp.assignHostId(AnyP::PROTO_HTTP);
    libecap::protocolHttps.assignHostId(AnyP::PROTO_HTTPS);
    libecap::protocolFtp.assignHostId(AnyP::PROTO_FTP);
    libecap::protocolGopher.assignHostId(AnyP::PROTO_GOPHER);
    libecap::protocolWais.assignHostId(AnyP::PROTO_WAIS);
    libecap::protocolUrn.assignHostId(AnyP::PROTO_URN);
    libecap::protocolWhois.assignHostId(AnyP::PROTO_WHOIS);
    protocolCacheObj.assignHostId(AnyP::PROTO_CACHE_OBJECT);
    protocolIcp.assignHostId(AnyP::PROTO_ICP);
#if USE_HTCP
    protocolHtcp.assignHostId(AnyP::PROTO_HTCP);
#endif
    protocolIcy.assignHostId(AnyP::PROTO_ICY);
    protocolUnknown.assignHostId(AnyP::PROTO_UNKNOWN);

    // allows adapter to safely ignore this in adapter::Service::configure()
    metaBypassable.assignHostId(1);
}

std::string
Adaptation::Ecap::Host::uri() const
{
    return "ecap://squid-cache.org/ecap/hosts/squid";
}

void
Adaptation::Ecap::Host::describe(std::ostream &os) const
{
    os << PACKAGE_NAME << " v" << PACKAGE_VERSION;
}

/// Strips libecap version components not affecting compatibility decisions.
static SBuf
EssentialVersion(const SBuf &raw)
{
    // all libecap x.y.* releases are supposed to be compatible so we strip
    // everything after the second period
    const SBuf::size_type minorPos = raw.find('.');
    const SBuf::size_type microPos = minorPos == SBuf::npos ?
                                     SBuf::npos : raw.find('.', minorPos+1);
    return raw.substr(0, microPos); // becomes raw if microPos is npos
}

/// If "their" libecap version is not compatible with what Squid has been built
/// with, then complain and return false.
static bool
SupportedVersion(const char *vTheir, const char *them)
{
    if (!vTheir || !*vTheir) {
        debugs(93, DBG_CRITICAL, "ERROR: Cannot use " << them <<
               " with libecap prior to v1.0.");
        return false;
    }

    // we support what we are built with
    const SBuf vSupported(LIBECAP_VERSION);
    debugs(93, 2, them << " with libecap v" << vTheir << "; us: v" << vSupported);

    if (EssentialVersion(SBuf(vTheir)) == EssentialVersion(vSupported))
        return true; // their version is supported

    debugs(93, DBG_CRITICAL, "ERROR: Cannot use " << them <<
           " with libecap v" << vTheir <<
           ": incompatible with supported libecap v" << vSupported);
    return false;
}

void
Adaptation::Ecap::Host::noteVersionedService(const char *vGiven, const libecap::weak_ptr<libecap::adapter::Service> &weak)
{
    /*
     * Check that libecap used to build the service is compatible with ours.
     * This has to be done using vGiven string and not Service object itself
     * because dereferencing a Service pointer coming from an unsupported
     * version is unsafe.
     */
    if (SupportedVersion(vGiven, "eCAP service built")) {
        Must(!weak.expired());
        RegisterAdapterService(weak.lock());
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
        return lv.normal() ? DBG_IMPORTANT : 2;

    return 2 + 2*lv.debugging() + 3*lv.operation() + 2*lv.xaction();
}

std::ostream *
Adaptation::Ecap::Host::openDebug(libecap::LogVerbosity lv)
{
    const int squidLevel = SquidLogLevel(lv);
    const int squidSection = 93; // XXX: this should be a global constant
    return Debug::Enabled(squidSection, squidLevel) ?
           &Debug::Start(squidSection, squidLevel) :
           nullptr;
}

void
Adaptation::Ecap::Host::closeDebug(std::ostream *debug)
{
    if (debug)
        Debug::Finish();
}

Adaptation::Ecap::Host::MessagePtr
Adaptation::Ecap::Host::newRequest() const
{
    static const MasterXaction::Pointer mx = new MasterXaction(XactionInitiator::initAdaptationOrphan_);
    return MessagePtr(new Adaptation::Ecap::MessageRep(new HttpRequest(mx)));
}

Adaptation::Ecap::Host::MessagePtr
Adaptation::Ecap::Host::newResponse() const
{
    return MessagePtr(new Adaptation::Ecap::MessageRep(new HttpReply));
}

void
Adaptation::Ecap::Host::Register()
{
    if (!TheHost && SupportedVersion(libecap::VersionString(),
                                     "Squid executable dynamically linked")) {
        TheHost.reset(new Adaptation::Ecap::Host);
        libecap::RegisterHost(TheHost);
    }
}

