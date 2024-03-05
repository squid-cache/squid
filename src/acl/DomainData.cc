/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 28    Access Control */

#include "squid.h"
#include "acl/Checklist.h"
#include "acl/DomainData.h"
#include "acl/SplayInserter.h"
#include "anyp/Uri.h"
#include "cache_cf.h"
#include "ConfigParser.h"
#include "debug/Stream.h"
#include "util.h"

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

bool
ACLDomainData::match(char const *host)
{
    if (host == nullptr)
        return 0;

    debugs(28, 3, "aclMatchDomainList: checking '" << host << "'");

    char *h = const_cast<char *>(host);
    char const * const * result = domains->find(h, aclHostDomainCompare);

    debugs(28, 3, "aclMatchDomainList: '" << host << "' " << (result ? "found" : "NOT found"));

    return (result != nullptr);
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

template <>
int
Acl::SplayInserter<char*>::Compare(const Value &a, const Value &b)
{
    // If X represents a set of matching domain names (e.g., .example.com), then
    // matchDomainName(X, Y) uses a single domain name from X by removing the
    // leading dot (e.g., example.com). We call that name "the root of X". If X
    // is a single domain name, then its root is X itself. Since domain sets
    // cannot have _partial_ overlaps (unlike IP or integer ranges), testing
    // roots is enough to detect duplicates and establish correct set order.

    if (matchDomainName(b, a)) {
        // Set A does not contain B's root. If set B contains A's root, then the
        // call below will return 0, signaling duplicates. Otherwise, A and B
        // have no common values, and the call below will correctly order the
        // two sets, mimicking the order used by the Splay comparison function
        // in match().
        return matchDomainName(a, b);
    } else {
        // Signal duplicates because set A contains B's root (at least).
        return 0;
    }
}

template <>
bool
Acl::SplayInserter<char*>::IsSubset(const Value &a, const Value &b)
{
    // A value that starts with a dot matches a set of the corresponding domain
    // names. Other values are individual domain names that match themselves.
    // \sa matchDomainName()

    if (*a == '.' && *b == '.') {
        // A and B are overlapping sets. More characters imply a smaller set.
        return strlen(a) >= strlen(b);
    }

    if (*a != '.' && *b != '.') {
        // A and B are identical individual domain names
        return true;
    }

    // Either A or B is a set. The other one is a domain name inside that set.
    // That domain name may use fewer or more characters (e.g., both example.com
    // and x.example.com domains belong to the same .example.com set), so we
    // cannot use a strlen()-based test here.
    return *b == '.';
}

template <>
Acl::SplayInserter<char*>::Value
Acl::SplayInserter<char*>::MakeCombinedValue(const Value &, const Value &)
{
    Assure(!"domain name sets cannot partially overlap");
    return nullptr; // unreachable code
}

template <>
void
Acl::SplayInserter<char*>::DestroyValue(Value v)
{
    xfree(v);
}

void
ACLDomainData::parse()
{
    if (!domains)
        domains = new Splay<char *>();

    while (char *t = ConfigParser::strtokFile()) {
        Tolower(t);
        Acl::SplayInserter<char*>::Merge(*domains, xstrdup(t));
    }
}

bool
ACLDomainData::empty() const
{
    return domains->empty();
}

