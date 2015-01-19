/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 28    Access Control */

#include "squid.h"
#include "acl/Checklist.h"
#include "acl/DomainData.h"
#include "cache_cf.h"
#include "Debug.h"
#include "src/URL.h"

template<class T>
inline void
xRefFree(T &thing)
{
    xfree (thing);
}

ACLDomainData::~ACLDomainData()
{
    if (domains) {
        domains->destroy(xRefFree);
        delete domains;
    }
}

template<class T>
inline int
splaystrcasecmp (T&l, T&r)
{
    return strcasecmp ((char *)l,(char *)r);
}

template<class T>
inline int
splaystrcmp (T&l, T&r)
{
    return strcmp ((char *)l,(char *)r);
}

/* general compare functions, these are used for tree search algorithms
 * so they return <0, 0 or >0 */

/* compare a host and a domain */

static int
aclHostDomainCompare( char *const &a, char * const &b)
{
    const char *h = static_cast<const char *>(a);
    const char *d = static_cast<const char *>(b);
    return matchDomainName(h, d);
}

/* compare two domains */

template<class T>
int
aclDomainCompare(T const &a, T const &b)
{
    char * const d1 = static_cast<char *>(b);
    char * const d2 = static_cast<char *>(a);
    int ret;
    ret = aclHostDomainCompare(d1, d2);

    if (ret != 0) {
        char *const d3 = d2;
        char *const d4 = d1;
        ret = aclHostDomainCompare(d3, d4);
        if (ret == 0) {
            // When a.example.com comes after .example.com in an ACL
            // sub-domain is ignored. That is okay. Just important
            bool d3big = (strlen(d3) > strlen(d4)); // Always suggest removing the longer one.
            debugs(28, DBG_IMPORTANT, "WARNING: '" << (d3big?d3:d4) << "' is a subdomain of '" << (d3big?d4:d3) << "'");
            debugs(28, DBG_IMPORTANT, "WARNING: You should remove '" << (d3big?d3:d4) << "' from the ACL named '" << AclMatchedName << "'");
            debugs(28, 2, HERE << "Ignore '" << d3 << "' to keep splay tree searching predictable");
        }
    } else if (ret == 0) {
        // It may be an exact duplicate. No problem. Just drop.
        if (strcmp(d1,d2)==0) {
            debugs(28, 2, "WARNING: '" << d2 << "' is duplicated in the list.");
            debugs(28, 2, "WARNING: You should remove one '" << d2 << "' from the ACL named '" << AclMatchedName << "'");
            return ret;
        }
        // When a.example.com comes before .example.com in an ACL
        // discarding the wildcard is critically bad.
        // or Maybe even both are wildcards. Things are very weird in those cases.
        bool d1big = (strlen(d1) > strlen(d2)); // Always suggest removing the longer one.
        debugs(28, DBG_CRITICAL, "ERROR: '" << (d1big?d1:d2) << "' is a subdomain of '" << (d1big?d2:d1) << "'");
        debugs(28, DBG_CRITICAL, "ERROR: You need to remove '" << (d1big?d1:d2) << "' from the ACL named '" << AclMatchedName << "'");
        self_destruct();
    }

    return ret;
}

bool
ACLDomainData::match(char const *host)
{
    if (host == NULL)
        return 0;

    debugs(28, 3, "aclMatchDomainList: checking '" << host << "'");

    char *h = const_cast<char *>(host);
    char const * const * result = domains->find(h, aclHostDomainCompare);

    debugs(28, 3, "aclMatchDomainList: '" << host << "' " << (result ? "found" : "NOT found"));

    return (result != NULL);
}

struct AclDomainDataDumpVisitor {
    SBufList contents;
    void operator() (char * const & node_data) {
        contents.push_back(SBuf(node_data));
    }
};

SBufList
ACLDomainData::dump() const
{
    AclDomainDataDumpVisitor visitor;
    domains->visit(visitor);
    return visitor.contents;
}

void
ACLDomainData::parse()
{
    char *t = NULL;

    if (!domains)
        domains = new Splay<char *>();

    while ((t = strtokFile())) {
        Tolower(t);
        domains->insert(xstrdup(t), aclDomainCompare);
    }
}

bool
ACLDomainData::empty() const
{
    return domains->empty();
}

ACLData<char const *> *
ACLDomainData::clone() const
{
    /* Splay trees don't clone yet. */
    assert (!domains);
    return new ACLDomainData;
}

