/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ACL_GADGETS_H
#define SQUID_ACL_GADGETS_H

#include "acl/forward.h"
#include "error/forward.h"

#include <sstream>

class ConfigParser;
class dlink_list;
class StoreEntry;
class wordlist;

/// Register an AclNode object for future deletion. Repeated registrations are OK.
/// \ingroup ACLAPI
void aclRegister(AclNode *acl);
/// \ingroup ACLAPI
void aclDestroyAccessList(acl_access **list);
/// \ingroup ACLAPI
void aclDestroyAcls(AclNode **);
/// \ingroup ACLAPI
void aclDestroyAclList(ACLList **);
/// Parses a single line of a "action followed by acls" directive (e.g., http_access).
/// \ingroup ACLAPI
void aclParseAccessLine(const char *directive, ConfigParser &parser, Acl::Tree **);
/// Parses a single line of a "some context followed by acls" directive (e.g., note n v).
/// The label parameter identifies the context (for debugging).
/// \returns the number of parsed ACL names
size_t aclParseAclList(ConfigParser &parser, Acl::Tree **, const char *label);
/// Template to convert various context labels to strings. \ingroup ACLAPI
template <class Any>
inline size_t
aclParseAclList(ConfigParser &parser, Acl::Tree **tree, const Any any)
{
    std::ostringstream buf;
    buf << any;
    return aclParseAclList(parser, tree, buf.str().c_str());
}

/// \ingroup ACLAPI
int aclIsProxyAuth(const char *name);
/// \ingroup ACLAPI
err_type aclGetDenyInfoPage(AclDenyInfoList ** head, const char *name, int redirect_allowed);
/// \ingroup ACLAPI
void aclParseDenyInfoLine(AclDenyInfoList **);
/// \ingroup ACLAPI
void aclDestroyDenyInfoList(AclDenyInfoList **);
/// \ingroup ACLAPI
wordlist *aclDumpGeneric(const AclNode *);
/// \ingroup ACLAPI
void aclCacheMatchFlush(dlink_list * cache);
/// \ingroup ACLAPI
void dump_acl_access(StoreEntry * entry, const char *name, acl_access * head);
/// \ingroup ACLAPI
void dump_acl_list(StoreEntry * entry, ACLList * head);

#endif /* SQUID_ACL_GADGETS_H */

