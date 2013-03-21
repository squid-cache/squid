#ifndef SQUID_ACL_GADGETS_H
#define SQUID_ACL_GADGETS_H

#include "err_type.h"

class acl_access;
class ACL;
class AclDenyInfoList;
class ACLList;
class ConfigParser;
class dlink_list;
class StoreEntry;
class wordlist;

/// \ingroup ACLAPI
void aclDestroyAccessList(acl_access **list);
/// \ingroup ACLAPI
void aclDestroyAcls(ACL **);
/// \ingroup ACLAPI
void aclDestroyAclList(ACLList **);
/// \ingroup ACLAPI
void aclParseAccessLine(ConfigParser &parser, acl_access **);
/// \ingroup ACLAPI
void aclParseAclList(ConfigParser &parser, ACLList **);
/// \ingroup ACLAPI
int aclIsProxyAuth(const char *name);
/// \ingroup ACLAPI
err_type aclGetDenyInfoPage(AclDenyInfoList ** head, const char *name, int redirect_allowed);
/// \ingroup ACLAPI
void aclParseDenyInfoLine(AclDenyInfoList **);
/// \ingroup ACLAPI
void aclDestroyDenyInfoList(AclDenyInfoList **);
/// \ingroup ACLAPI
wordlist *aclDumpGeneric(const ACL *);
/// \ingroup ACLAPI
void aclCacheMatchFlush(dlink_list * cache);
/// \ingroup ACLAPI
void dump_acl_access(StoreEntry * entry, const char *name, acl_access * head);
/// \ingroup ACLAPI
void dump_acl_list(StoreEntry * entry, ACLList * head);

#endif /* SQUID_ACL_GADGETS_H */
