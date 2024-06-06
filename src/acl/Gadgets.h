/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_ACL_GADGETS_H
#define SQUID_SRC_ACL_GADGETS_H

#include "acl/forward.h"
#include "error/forward.h"
#include "sbuf/forward.h"

#include <optional>
#include <sstream>

class ConfigParser;
class dlink_list;
class StoreEntry;
class wordlist;

/// \ingroup ACLAPI
void aclDestroyAccessList(acl_access **list);
/// \ingroup ACLAPI
void aclDestroyAclList(ACLList **);

/// Parses a single line of a "action followed by acls" directive (e.g., http_access).
void aclParseAccessLine(const char *directive, ConfigParser &, acl_access **);

/// Parses a single line of a "some context followed by acls" directive (e.g., note n v).
/// The label parameter identifies the context (for debugging).
/// \returns the number of parsed ACL names
size_t aclParseAclList(ConfigParser &, ACLList **, const char *label);

/// Template to convert various context labels to strings. \ingroup ACLAPI
template <class Any>
inline size_t
aclParseAclList(ConfigParser &parser, ACLList ** const tree, const Any any)
{
    std::ostringstream buf;
    buf << any;
    return aclParseAclList(parser, tree, buf.str().c_str());
}

/// Whether the given name names an Acl::Node object with true isProxyAuth() result.
/// This is a safe variation of Acl::Node::FindByName(*name)->isProxyAuth().
bool aclIsProxyAuth(const std::optional<SBuf> &name);

/// The first configured deny_info error page ID matching the given access check outcome (or ERR_NONE).
/// \param allowCustomStatus whether to consider deny_info rules containing custom HTTP response status code
err_type FindDenyInfoPage(const Acl::Answer &, bool allowCustomStatus);

/// \ingroup ACLAPI
void aclParseDenyInfoLine(AclDenyInfoList **);
/// \ingroup ACLAPI
void aclDestroyDenyInfoList(AclDenyInfoList **);
/// \ingroup ACLAPI
wordlist *aclDumpGeneric(const Acl::Node *);
/// \ingroup ACLAPI
void aclCacheMatchFlush(dlink_list * cache);
/// \ingroup ACLAPI
void dump_acl_access(StoreEntry * entry, const char *name, acl_access * head);
/// \ingroup ACLAPI
void dump_acl_list(StoreEntry * entry, ACLList * head);

namespace Acl {
/// convenient and safe access to a stored (and parsed/configured) Tree
/// \returns **cfg or *cfg->getRaw()
/// \prec cfg points to a non-nil TreePointer object; ACL parsing code is
/// written so that ToTree() caller may just check that cfg itself is not nil
/// (because parsing code never stores nil TreePointer objects).
const Tree &ToTree(const TreePointer *cfg);
}

#endif /* SQUID_SRC_ACL_GADGETS_H */

