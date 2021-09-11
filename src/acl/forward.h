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
class NotNode;
class OrNode;
class Tree;

using TreePointer = RefCount<Acl::Tree>;
using NodePointer = RefCount<Acl::Node>;

class NamedRules;

/// prepares to parse ACLs configuration
void Init(void);

} // namespace Acl

typedef void ACLCB(Acl::Answer, void *);

/// deprecated; use Acl::TreePointer directly
class acl_access {
public:
    RefCount<Acl::Tree> raw;
};

/// deprecated; use Acl::TreePointer directly
using ACLList = acl_access;

class ExternalACLEntry;
typedef RefCount<ExternalACLEntry> ExternalACLEntryPointer;

#endif /* SQUID_SRC_ACL_FORWARD_H */

