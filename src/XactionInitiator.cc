/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "cfg/Exceptions.h"
#include "sbuf/Stream.h"
#include "XactionInitiator.h"

#include <map>
#include <string>

XactionInitiator::Initiators
XactionInitiator::ParseInitiators(const char *name)
{
    typedef std::map<std::string, XactionInitiator::Initiators> InitiatorsMap;
    static InitiatorsMap SupportedInitiators = {
        {"client", initClient},
        {"peer-pool", initPeerPool},
        {"certificate-fetching", initCertFetcher},
        {"esi", initEsi},
        {"cache-digest", initCacheDigest},
        {"server", initServer},
        {"htcp", initHtcp},
        {"icp", initIcp},
        {"icmp", initIcmp},
        {"asn", initAsn},
        {"ipc", initIpc},
        {"adaptation", initAdaptation},
        {"icon", initIcon},
        {"peer-mcast", initPeerMcast},
        {"internal", InternalInitiators()},
        {"all", AllInitiators()}
    };
    const auto it = SupportedInitiators.find(name);
    if (it == SupportedInitiators.cend())
        throw Cfg::FatalError(ToSBuf("invalid transaction_initiator '", name, "'"));
    return it->second;
}

