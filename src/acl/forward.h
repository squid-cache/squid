#ifndef SQUID_ACL_FORWARD_H
#define SQUID_ACL_FORWARD_H

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

// XXX: remove after review and before commit, after renaming all users?
#define acl_access Acl::Tree
#define ACLList Acl::Tree

#endif /* SQUID_ACL_FORWARD_H */
