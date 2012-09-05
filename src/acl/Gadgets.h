#ifndef SQUID_ACL_GADGETS_H
#define SQUID_ACL_GADGETS_H

#include "err_type.h"

struct dlink_list;
class acl_access;
class ACL;
class AclDenyInfoList;
class ACLList;
class ConfigParser;
class StoreEntry;
class wordlist;

/// \ingroup ACLAPI
extern void aclDestroyAccessList(acl_access **list);
/// \ingroup ACLAPI
extern void aclDestroyAcls(ACL **);
/// \ingroup ACLAPI
extern void aclDestroyAclList(ACLList **);
/// \ingroup ACLAPI
extern void aclParseAccessLine(ConfigParser &parser, acl_access **);
/// \ingroup ACLAPI
extern void aclParseAclList(ConfigParser &parser, ACLList **);
/// \ingroup ACLAPI
extern int aclIsProxyAuth(const char *name);
/// \ingroup ACLAPI
extern err_type aclGetDenyInfoPage(AclDenyInfoList ** head, const char *name, int redirect_allowed);
/// \ingroup ACLAPI
extern void aclParseDenyInfoLine(AclDenyInfoList **);
/// \ingroup ACLAPI
extern void aclDestroyDenyInfoList(AclDenyInfoList **);
/// \ingroup ACLAPI
extern wordlist *aclDumpGeneric(const ACL *);
/// \ingroup ACLAPI
extern void aclCacheMatchFlush(dlink_list * cache);
/// \ingroup ACLAPI
extern void dump_acl_access(StoreEntry * entry, const char *name, acl_access * head);
/// \ingroup ACLAPI
extern void dump_acl_list(StoreEntry * entry, ACLList * head);

#endif /* SQUID_ACL_GADGETS_H */
