#ifndef SQUID_AUTH_ACL_H
#define SQUID_AUTH_ACL_H

// ACL-related code used by authentication-related code. This code is not in
// auth/Gadgets to avoid making auth/libauth dependent on acl/libstate because
// acl/libstate already depends on auth/libauth.

class ACLChecklist;
/// \ingroup AuthAPI
extern int AuthenticateAcl(ACLChecklist *ch);

#endif /* SQUID_AUTH_ACL_H */
