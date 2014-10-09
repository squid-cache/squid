#ifndef SQUID_ACL_FORWARD_H
#define SQUID_ACL_FORWARD_H

#include "base/RefCount.h"

class ACL;
class ACLChecklist;
class ACLFilledChecklist;
class ACLList;

class AclAddress;
class AclDenyInfoList;
class AclSizeLimit;

namespace Acl
{

class InnerNode;
class NotNode;
class AndNode;
class OrNode;
class Tree;

} // namespace Acl

#define ACL_NAME_SZ 64

// TODO: Consider renaming all users and removing. Cons: hides the difference
// between ACLList tree without actions and acl_access Tree with actions.
#define acl_access Acl::Tree
#define ACLList Acl::Tree

class ExternalACLEntry;
typedef RefCount<ExternalACLEntry> ExternalACLEntryPointer;

#endif /* SQUID_ACL_FORWARD_H */
