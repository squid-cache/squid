#ifndef SQUID_ACL_GADGETS_H
#define SQUID_ACL_GADGETS_H

#include "config.h"
#include "enums.h" /* for err_type */

struct dlink_list;
class StoreEntry;
class ConfigParser;
class acl_access;
class ACL;
class ACLList;
struct acl_deny_info_list;
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
extern err_type aclGetDenyInfoPage(acl_deny_info_list ** head, const char *name, int redirect_allowed);
/// \ingroup ACLAPI
extern void aclParseDenyInfoLine(acl_deny_info_list **);
/// \ingroup ACLAPI
extern void aclDestroyDenyInfoList(acl_deny_info_list **);
/// \ingroup ACLAPI
extern wordlist *aclDumpGeneric(const ACL *);
/// \ingroup ACLAPI
extern void aclCacheMatchFlush(dlink_list * cache);
/// \ingroup ACLAPI
extern void dump_acl_access(StoreEntry * entry, const char *name, acl_access * head);

#endif /* SQUID_ACL_GADGETS_H */
