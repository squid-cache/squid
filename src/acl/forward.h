/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_ACL_FORWARD_H
#define SQUID_SRC_ACL_FORWARD_H

#include "base/RefCount.h"

class ACLChecklist;
class ACLFilledChecklist;

class AclDenyInfoList;
class AclSizeLimit;

namespace Acl
{

class Node;
class Address;
class AndNode;
class Answer;
class ChecklistFiller;
class InnerNode;
class NamedAcls;
class NotNode;
class OrNode;
class Tree;

/// prepares to parse ACLs configuration
void Init(void);

/// reconfiguration-safe storage of ACL rules
using TreePointer = RefCount<Acl::Tree>;

} // namespace Acl

typedef void ACLCB(Acl::Answer, void *);

// TODO: Consider renaming all users and removing. Cons: hides the difference
// between ACLList tree without actions and acl_access Tree with actions.
using acl_access = Acl::TreePointer;
using ACLList = Acl::TreePointer;

class ExternalACLEntry;
typedef RefCount<ExternalACLEntry> ExternalACLEntryPointer;

#endif /* SQUID_SRC_ACL_FORWARD_H */

