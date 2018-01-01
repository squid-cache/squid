/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"

#define STUB_API "auth/libacls.la"
#include "STUB.h"

#if USE_AUTH
#include "acl/Acl.h" /* for allow_t */

#include "auth/Acl.h"
allow_t AuthenticateAcl(ACLChecklist *) STUB_RETVAL(ACCESS_DENIED)

#include "auth/AclMaxUserIp.h"
ACL * ACLMaxUserIP::clone() const STUB_RETVAL(NULL)
ACLMaxUserIP::ACLMaxUserIP (char const *) STUB
char const * ACLMaxUserIP::typeString() const STUB_RETVAL(NULL)
bool ACLMaxUserIP::empty () const STUB_RETVAL(false)
bool ACLMaxUserIP::valid () const STUB_RETVAL(false)
void ACLMaxUserIP::parse() STUB
int ACLMaxUserIP::match(Auth::UserRequest::Pointer, Ip::Address const &) STUB_RETVAL(0)
int ACLMaxUserIP::match(ACLChecklist *) STUB_RETVAL(0)
SBufList ACLMaxUserIP::dump() const STUB_RETVAL(SBufList())
const Acl::Options &ACLMaxUserIP::options() STUB_RETVAL(Acl::NoOptions())

#include "auth/AclProxyAuth.h"
ACLProxyAuth::~ACLProxyAuth() STUB
ACLProxyAuth::ACLProxyAuth(ACLData<char const *> *, char const *) STUB
ACLProxyAuth::ACLProxyAuth (ACLProxyAuth const &) STUB
ACLProxyAuth & ACLProxyAuth::operator= (ACLProxyAuth const & a) STUB_RETVAL(const_cast<ACLProxyAuth &>(a))
char const * ACLProxyAuth::typeString() const STUB_RETVAL(NULL)
void ACLProxyAuth::parse() STUB
int ACLProxyAuth::match(ACLChecklist *) STUB_RETVAL(0)
SBufList ACLProxyAuth::dump() const STUB_RETVAL(SBufList())
bool ACLProxyAuth::empty () const STUB_RETVAL(false)
bool ACLProxyAuth::valid () const STUB_RETVAL(false)
ProxyAuthLookup * ProxyAuthLookup::Instance() STUB_RETVAL(NULL)
void ProxyAuthLookup::checkForAsync(ACLChecklist *) const STUB
void ProxyAuthLookup::LookupDone(void *) STUB
ACL * ACLProxyAuth::clone() const STUB_RETVAL(NULL)
int ACLProxyAuth::matchForCache(ACLChecklist *) STUB_RETVAL(0)
int ACLProxyAuth::matchProxyAuth(ACLChecklist *) STUB_RETVAL(0)
void ACLProxyAuth::parseFlags() STUB

#endif /* USE_AUTH */

