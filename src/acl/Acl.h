/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ACL_H
#define SQUID_ACL_H

#include "acl/forward.h"
#include "acl/Options.h"
#include "cbdata.h"
#include "defines.h"
#include "dlink.h"
#include "sbuf/forward.h"

#include <algorithm>
#include <ostream>

class ConfigParser;

namespace Acl {

/// the ACL type name known to admins
typedef const char *TypeName;
/// a "factory" function for making ACL objects (of some ACL child type)
typedef ACL *(*Maker)(TypeName typeName);
/// use the given ACL Maker for all ACLs of the named type
void RegisterMaker(TypeName typeName, Maker maker);

} // namespace Acl

/// A configurable condition. A node in the ACL expression tree.
/// Can evaluate itself in FilledChecklist context.
/// Does not change during evaluation.
/// \ingroup ACLAPI
class ACL
{

public:
    void *operator new(size_t);
    void operator delete(void *);

    static void ParseAclLine(ConfigParser &parser, ACL ** head);
    static void Initialize();
    static ACL *FindByName(const char *name);

    ACL();
    virtual ~ACL();

    /// sets user-specified ACL name and squid.conf context
    void context(const char *name, const char *configuration);

    /// Orchestrates matching checklist against the ACL using match(),
    /// after checking preconditions and while providing debugging.
    /// \return true if and only if there was a successful match.
    /// Updates the checklist state on match, async, and failure.
    bool matches(ACLChecklist *checklist) const;

    /// \returns (linked) Options supported by this ACL
    virtual const Acl::Options &options() { return Acl::NoOptions(); }

    /// configures ACL options, throwing on configuration errors
    virtual void parseFlags();

    /// parses node representation in squid.conf; dies on failures
    virtual void parse() = 0;
    virtual char const *typeString() const = 0;
    virtual bool isProxyAuth() const;
    virtual SBufList dump() const = 0;
    virtual bool empty() const = 0;
    virtual bool valid() const;

    int cacheMatchAcl(dlink_list * cache, ACLChecklist *);
    virtual int matchForCache(ACLChecklist *checklist);

    virtual void prepareForUse() {}

    SBufList dumpOptions(); ///< \returns approximate options configuration

    char name[ACL_NAME_SZ];
    char *cfgline;
    ACL *next; // XXX: remove or at least use refcounting
    bool registered; ///< added to the global list of ACLs via aclRegister()

private:
    /// Matches the actual data in checklist against this ACL.
    virtual int match(ACLChecklist *checklist) = 0; // XXX: missing const

    /// whether our (i.e. shallow) match() requires checklist to have a AccessLogEntry
    virtual bool requiresAle() const;
    /// whether our (i.e. shallow) match() requires checklist to have a request
    virtual bool requiresRequest() const;
    /// whether our (i.e. shallow) match() requires checklist to have a reply
    virtual bool requiresReply() const;
};

/// \ingroup ACLAPI
typedef enum {
    // Authorization ACL result states
    ACCESS_DENIED,
    ACCESS_ALLOWED,
    ACCESS_DUNNO,

    // Authentication ACL result states
    ACCESS_AUTH_REQUIRED,    // Missing Credentials
} aclMatchCode;

/// \ingroup ACLAPI
/// ACL check answer
namespace Acl {

class Answer
{
public:
    // not explicit: allow "aclMatchCode to Acl::Answer" conversions (for now)
    Answer(const aclMatchCode aCode, int aKind = 0): code(aCode), kind(aKind) {}

    Answer(): code(ACCESS_DUNNO), kind(0) {}

    bool operator ==(const aclMatchCode aCode) const {
        return code == aCode;
    }

    bool operator !=(const aclMatchCode aCode) const {
        return !(*this == aCode);
    }

    bool operator ==(const Answer allow) const {
        return code == allow.code && kind == allow.kind;
    }

    operator aclMatchCode() const {
        return code;
    }

    /// Whether an "allow" rule matched. If in doubt, use this popular method.
    /// Also use this method to treat exceptional ACCESS_DUNNO and
    /// ACCESS_AUTH_REQUIRED outcomes as if a "deny" rule matched.
    /// See also: denied().
    bool allowed() const { return code == ACCESS_ALLOWED; }

    /// Whether a "deny" rule matched. Avoid this rarely used method.
    /// Use this method (only) to treat exceptional ACCESS_DUNNO and
    /// ACCESS_AUTH_REQUIRED outcomes as if an "allow" rule matched.
    /// See also: allowed().
    bool denied() const { return code == ACCESS_DENIED; }

    /// whether Squid is uncertain about the allowed() or denied() answer
    bool conflicted() const { return !allowed() && !denied(); }

    aclMatchCode code; ///< ACCESS_* code
    int kind; ///< which custom access list verb matched
};

} // namespace Acl

inline std::ostream &
operator <<(std::ostream &o, const Acl::Answer a)
{
    switch (a) {
    case ACCESS_DENIED:
        o << "DENIED";
        break;
    case ACCESS_ALLOWED:
        o << "ALLOWED";
        break;
    case ACCESS_DUNNO:
        o << "DUNNO";
        break;
    case ACCESS_AUTH_REQUIRED:
        o << "AUTH_REQUIRED";
        break;
    }
    return o;
}

/// \ingroup ACLAPI
class acl_proxy_auth_match_cache
{
    MEMPROXY_CLASS(acl_proxy_auth_match_cache);

public:
    acl_proxy_auth_match_cache(int matchRv, void * aclData) :
        matchrv(matchRv),
        acl_data(aclData)
    {}

    dlink_node link;
    int matchrv;
    void *acl_data;
};

/// \ingroup ACLAPI
/// XXX: find a way to remove or at least use a refcounted ACL pointer
extern const char *AclMatchedName;  /* NULL */

#endif /* SQUID_ACL_H */

