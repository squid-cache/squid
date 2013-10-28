#include "squid.h"

#define STUB_API "auth/libacls.la"
#include "STUB.h"

#include "acl/Acl.h" /* for allow_t */

#include "auth/Acl.h"
allow_t AuthenticateAcl(ACLChecklist *) STUB

#include "auth/AclMaxUserIp.h"
ACL * ACLMaxUserIP::clone() const STUB
ACLMaxUserIP::ACLMaxUserIP (char const *) STUB
ACLMaxUserIP::ACLMaxUserIP (ACLMaxUserIP const &) STUB
ACLMaxUserIP::~ACLMaxUserIP() STUB
char const * ACLMaxUserIP::typeString() const STUB
bool ACLMaxUserIP::empty () const STUB
bool ACLMaxUserIP::valid () const STUB
void ACLMaxUserIP::parse() STUB
int ACLMaxUserIP::match(Auth::UserRequest::Pointer, Ip::Address const &) STUB
int ACLMaxUserIP::match(ACLChecklist *) STUB
wordlist * ACLMaxUserIP::dump() const STUB

#include "auth/AclProxyAuth.h"
ACLProxyAuth::~ACLProxyAuth() STUB
ACLProxyAuth::ACLProxyAuth(ACLData<char const *> *, char const *) STUB
ACLProxyAuth::ACLProxyAuth (ACLProxyAuth const &) STUB
ACLProxyAuth & ACLProxyAuth::operator= (ACLProxyAuth const &) STUB
char const * ACLProxyAuth::typeString() const STUB
void ACLProxyAuth::parse() STUB
int ACLProxyAuth::match(ACLChecklist *) STUB
wordlist * ACLProxyAuth::dump() const STUB
bool ACLProxyAuth::empty () const STUB
bool ACLProxyAuth::valid () const STUB
ProxyAuthLookup * ProxyAuthLookup::Instance() STUB
void ProxyAuthLookup::checkForAsync(ACLChecklist *) const STUB
void ProxyAuthLookup::LookupDone(void *) STUB
ACL * ACLProxyAuth::clone() const STUB
int ACLProxyAuth::matchForCache(ACLChecklist *) STUB
int ACLProxyAuth::matchProxyAuth(ACLChecklist *) STUB
