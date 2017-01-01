/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 28    Access Control */

#include "squid.h"
#include "acl/Checklist.h"
#include "acl/DomainData.h"
#include "acl/RegexData.h"
#include "acl/ServerName.h"
#include "client_side.h"
#include "fde.h"
#include "HttpRequest.h"
#include "ipcache.h"
#include "SquidString.h"
#include "ssl/bio.h"
#include "ssl/ServerBump.h"
#include "ssl/support.h"
#include "URL.h"

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
    if (host == NULL)
        return 0;

    debugs(28, 3, "checking '" << host << "'");

    char *h = const_cast<char *>(host);
    char const * const * result = domains->find(h, aclHostDomainCompare);

    debugs(28, 3, "'" << host << "' " << (result ? "found" : "NOT found"));

    return (result != NULL);

}

ACLData<char const *> *
ACLServerNameData::clone() const
{
    /* Splay trees don't clone yet. */
    assert (!domains);
    return new ACLServerNameData;
}

/// A helper function to be used with Ssl::matchX509CommonNames().
/// \retval 0 when the name (cn or an alternate name) matches acl data
/// \retval 1 when the name does not match
template<class MatchType>
int
check_cert_domain( void *check_data, ASN1_STRING *cn_data)
{
    char cn[1024];
    ACLData<MatchType> * data = (ACLData<MatchType> *)check_data;

    if (cn_data->length > (int)sizeof(cn) - 1)
        return 1; // ignore data that does not fit our buffer

    char *s = reinterpret_cast<char *>(cn_data->data);
    char *d = cn;
    for (int i = 0; i < cn_data->length; ++i, ++d, ++s) {
        if (*s == '\0')
            return 1; // always a domain mismatch. contains 0x00
        *d = *s;
    }
    cn[cn_data->length] = '\0';
    debugs(28, 4, "Verifying certificate name/subjectAltName " << cn);
    if (data->match(cn))
        return 0;
    return 1;
}

int
ACLServerNameStrategy::match (ACLData<MatchType> * &data, ACLFilledChecklist *checklist, ACLFlags &flags)
{
    assert(checklist != NULL && checklist->request != NULL);

    const char *serverName = NULL;
    SBuf serverNameKeeper; // because c_str() is not constant
    if (ConnStateData *conn = checklist->conn()) {
        if (conn->serverBump()) {
            if (X509 *peer_cert = conn->serverBump()->serverCert.get())
                return Ssl::matchX509CommonNames(peer_cert, (void *)data, check_cert_domain<MatchType>);
        }

        if (conn->sslCommonName().isEmpty()) {
            const char *host = checklist->request->GetHost();
            if (host && *host) // paranoid first condition: host() is never nil
                serverName = host;
        } else {
            serverNameKeeper = conn->sslCommonName();
            serverName = serverNameKeeper.c_str();
        }
    }

    if (!serverName)
        serverName = "none";

    return data->match(serverName);
}

ACLServerNameStrategy *
ACLServerNameStrategy::Instance()
{
    return &Instance_;
}

ACLServerNameStrategy ACLServerNameStrategy::Instance_;

