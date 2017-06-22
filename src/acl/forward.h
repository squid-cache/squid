/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ACL_FORWARD_H
#define SQUID_ACL_FORWARD_H

#include "base/RefCount.h"

class ACL;
class ACLChecklist;
class ACLFilledChecklist;
class ACLList;

class AclDenyInfoList;
class AclSizeLimit;

namespace Acl
{

class Address;
class InnerNode;
class NotNode;
class AndNode;
class OrNode;
class Tree;

/// prepares to parse ACLs configuration
void Init(void);

} // namespace Acl

class allow_t;
typedef void ACLCB(allow_t, void *);

#define ACL_NAME_SZ 64

// TODO: Consider renaming all users and removing. Cons: hides the difference
// between ACLList tree without actions and acl_access Tree with actions.
#define acl_access Acl::Tree
#define ACLList Acl::Tree

class ExternalACLEntry;
typedef RefCount<ExternalACLEntry> ExternalACLEntryPointer;

#endif /* SQUID_ACL_FORWARD_H */

