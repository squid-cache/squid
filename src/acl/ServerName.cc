/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 28    Access Control */

#include "squid.h"
#include "acl/FilledChecklist.h"
#include "acl/ServerName.h"
#include "client_side.h"
#include "http/Stream.h"
#include "HttpRequest.h"
#include "ssl/bio.h"
#include "ssl/ServerBump.h"
#include "ssl/support.h"

// Compare function for tree search algorithms
static int
aclHostDomainCompare( char *const &a, char * const &b)
{
    const char *h = static_cast<const char *>(a);
    const char *d = static_cast<const char *>(b);
    debugs(28, 7, "Match:" << h << " <>  " << d);
    return matchDomainName(h, d, mdnHonorWildcards);
}

bool
ACLServerNameData::match(const char *host)
{
    if (host == nullptr)
        return 0;

    debugs(28, 3, "checking '" << host << "'");

    char *h = const_cast<char *>(host);
    char const * const * result = domains->find(h, aclHostDomainCompare);

    debugs(28, 3, "'" << host << "' " << (result ? "found" : "NOT found"));

    return (result != nullptr);

}

namespace Acl {

class ServerNameMatcher: public Ssl::GeneralNameMatcher
{
public:
    explicit ServerNameMatcher(ServerNameCheck::Parameters &p): parameters(p) {}

protected:
    /* GeneralNameMatcher API */
    bool matchDomainName(const SBuf &) const override;
    bool matchIp(const Ip::Address &) const override;

private:
    // TODO: Make ServerNameCheck::Parameters::match() and this reference constant.
    ServerNameCheck::Parameters &parameters; ///< configured ACL parameters
};

} // namespace Acl

bool
Acl::ServerNameMatcher::matchDomainName(const SBuf &domain) const
{
    return parameters.match(SBuf(domain).c_str()); // TODO: Upgrade string-matching ACLs to SBuf
}

bool
Acl::ServerNameMatcher::matchIp(const Ip::Address &ip) const
{
    // We are given an Ip::Address, but our ACL parameters use case-sensitive
    // string equality or regex string matches. There are many ways to convert
    // an IPv6 address to a string, but only one format can correctly match
    // certain configured parameters. Our ssl::server_name docs request the
    // following ACL parameter formatting (that this to-string conversion code
    // produces): IPv6 addresses are bracketed and use "::" notation (where
    // applicable).
    //
    // Similar problems affect dstdomain ACLs. TODO: Instead of relying on users
    // reading docs and following their inet_ntop(3) implementation to match
    // IPv6 addresses handled by matchDomainName(), enhance matchDomainName()
    // code and ACL parameter storage to support Ip::Address objects.
    char hostStr[MAX_IPSTRLEN] = "";
    (void)ip.toHostStr(hostStr, sizeof(hostStr));
    return parameters.match(hostStr);
}

int
Acl::ServerNameCheck::match(ACLChecklist * const ch)
{
    const auto checklist = Filled(ch);

    assert(checklist != nullptr && checklist->request != nullptr);

    std::optional<SBuf> serverNameFromConn;
    if (ConnStateData *conn = checklist->conn()) {
        std::optional<SBuf> clientRequestedServerName;
        const auto &clientSni = conn->tlsClientSni();
        if (clientSni.isEmpty()) {
            const char *host = checklist->request->url.host();
            if (host && *host) // paranoid first condition: host() is never nil
                clientRequestedServerName = host; // TODO: Use Uri::hostOrIp() instead
        } else
            clientRequestedServerName = clientSni;

        if (useConsensus) {
            X509 *peer_cert = conn->serverBump() ? conn->serverBump()->serverCert.get() : nullptr;
            // use the client requested name if it matches the server
            // certificate or if the certificate is not available
            if (!peer_cert || !clientRequestedServerName ||
                    Ssl::findSubjectName(*peer_cert, *clientRequestedServerName))
                serverNameFromConn = clientRequestedServerName;
        } else if (useClientRequested)
            serverNameFromConn = clientRequestedServerName;
        else { // either no options or useServerProvided
            if (X509 *peer_cert = (conn->serverBump() ? conn->serverBump()->serverCert.get() : nullptr))
                return Ssl::findMatchingSubjectName(*peer_cert, ServerNameMatcher(*data));
            if (!useServerProvided)
                serverNameFromConn = clientRequestedServerName;
        }
    }

    const auto serverName = serverNameFromConn ? serverNameFromConn->c_str() : "none";
    return data->match(serverName);
}

const Acl::Options &
Acl::ServerNameCheck::options()
{
    static const Acl::BooleanOption ClientRequested("--client-requested");
    static const Acl::BooleanOption ServerProvided("--server-provided");
    static const Acl::BooleanOption Consensus("--consensus");
    static const Acl::Options MyOptions = { &ClientRequested, &ServerProvided, &Consensus };
    ClientRequested.linkWith(&useClientRequested);
    ServerProvided.linkWith(&useServerProvided);
    Consensus.linkWith(&useConsensus);
    return MyOptions;
}

bool
Acl::ServerNameCheck::valid() const
{
    int optionCount = 0;

    if (useClientRequested)
        optionCount++;
    if (useServerProvided)
        optionCount++;
    if (useConsensus)
        optionCount++;

    if (optionCount > 1) {
        debugs(28, DBG_CRITICAL, "ERROR: Multiple options given for the server_name ACL");
        return false;
    }
    return true;
}

