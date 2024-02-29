/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_ACL_ACL_H
#define SQUID_SRC_ACL_ACL_H

#include "acl/forward.h"
#include "defines.h"
#include "dlink.h"
#include "sbuf/forward.h"

#include <algorithm>
#include <ostream>

namespace Acl {

/// the ACL type name known to admins
using TypeName = const char *;
/// a "factory" function for making Acl::Node objects (of some Node child type)
using Maker = Node *(*)(TypeName typeName);
/// use the given Acl::Node Maker for all ACLs of the named type
void RegisterMaker(TypeName typeName, Maker maker);

/// Validate and store the ACL key parameter for ACL types
/// declared using "acl aclname type key argument..." declaration that
/// require unique key values (if any) for each aclname+type combination.
/// Key comparison is case-insensitive.
void SetKey(SBuf &keyStorage, const char *keyParameterName, const char *newKey);

}  // namespace Acl

/// \ingroup ACLAPI
typedef enum {
    // Authorization ACL result states
    ACCESS_DENIED,
    ACCESS_ALLOWED,
    ACCESS_DUNNO,

    // Authentication Acl::Node result states
    ACCESS_AUTH_REQUIRED,    // Missing Credentials
} aclMatchCode;

/// \ingroup ACLAPI
/// Acl::Node check answer
namespace Acl {

class Answer
{
public:
    // TODO: Find a good way to avoid implicit conversion (without explicitly
    // casting every ACCESS_ argument in implicit constructor calls).
    Answer(const aclMatchCode aCode, int aKind = 0): code(aCode), kind(aKind) {}

    Answer() = default;

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

    aclMatchCode code = ACCESS_DUNNO; ///< ACCESS_* code

    /// the matched custom access list verb (or zero)
    int kind = 0;

    /// whether we were computed by the "negate the last explicit action" rule
    bool implicit = false;
};

inline std::ostream &
operator <<(std::ostream &o, const Answer a)
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

} // namespace Acl

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
/// XXX: find a way to remove or at least use a refcounted Acl::Node pointer
extern const char *AclMatchedName;  /* NULL */

#endif /* SQUID_SRC_ACL_ACL_H */

