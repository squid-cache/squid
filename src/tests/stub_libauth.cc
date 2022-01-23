/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"

#define STUB_API "auth/libauth.la"
#include "tests/STUB.h"

#if USE_AUTH
#include "auth/SchemeConfig.h"
namespace Auth
{
Auth::UserRequest::Pointer SchemeConfig::CreateAuthUser(const char *, AccessLogEntry::Pointer &al) STUB_RETVAL(NULL)
Auth::SchemeConfig * SchemeConfig::Find(const char *) STUB_RETVAL(NULL)
void SchemeConfig::registerWithCacheManager(void) STUB_NOP
Auth::ConfigVector TheConfig;
}

#include "auth/Gadgets.h"
int authenticateActiveSchemeCount(void) STUB_RETVAL(0)
int authenticateSchemeCount(void) STUB_RETVAL(0)
void authenticateInit(Auth::ConfigVector *) STUB
void authenticateRotate(void) STUB
void authenticateReset(void) STUB

#include "auth/Scheme.h"
#include <vector>
std::vector<Auth::Scheme::Pointer> *Auth::Scheme::_Schemes = NULL;
void Auth::Scheme::AddScheme(Auth::Scheme::Pointer) STUB
Auth::Scheme::Pointer Auth::Scheme::Find(const char *) STUB_RETVAL(NULL)
std::vector<Auth::Scheme::Pointer> & Auth::Scheme::GetSchemes() STUB_RETVAL(*_Schemes);
void Auth::Scheme::FreeAll() STUB

#include "auth/SchemesConfig.h"
void Auth::SchemesConfig::expand() STUB

#include "auth/User.h"
Auth::User::User(Auth::SchemeConfig *, const char *) STUB
Auth::CredentialState Auth::User::credentials() const STUB_RETVAL(credentials_state)
void Auth::User::credentials(CredentialState) STUB
void Auth::User::absorb(Auth::User::Pointer) STUB
Auth::User::~User() STUB_NOP
void Auth::User::clearIp() STUB
void Auth::User::removeIp(Ip::Address) STUB
void Auth::User::addIp(Ip::Address) STUB
void Auth::User::CredentialsCacheStats(StoreEntry *) STUB

#include "auth/UserRequest.h"
char const * Auth::UserRequest::username() const STUB_RETVAL("stub_username")
void Auth::UserRequest::start(HttpRequest *, AccessLogEntry::Pointer &, AUTHCB *, void *) STUB
bool Auth::UserRequest::valid() const STUB_RETVAL(false)
void * Auth::UserRequest::operator new (size_t) STUB_RETVAL((void *)1)
void Auth::UserRequest::operator delete (void *) STUB
Auth::UserRequest::UserRequest() STUB
Auth::UserRequest::~UserRequest() STUB
void Auth::UserRequest::setDenyMessage(char const *) STUB
char const * Auth::UserRequest::getDenyMessage() const STUB_RETVAL("stub")
char const * Auth::UserRequest::denyMessage(char const * const) const STUB_RETVAL("stub")
void authenticateAuthUserRequestRemoveIp(Auth::UserRequest::Pointer, Ip::Address const &) STUB
void authenticateAuthUserRequestClearIp(Auth::UserRequest::Pointer) STUB
int authenticateAuthUserRequestIPCount(Auth::UserRequest::Pointer) STUB_RETVAL(0)
int authenticateUserAuthenticated(Auth::UserRequest::Pointer) STUB_RETVAL(0)
Auth::Direction Auth::UserRequest::direction() STUB_RETVAL(Auth::CRED_ERROR)
void Auth::UserRequest::addAuthenticationInfoHeader(HttpReply *, int) STUB
void Auth::UserRequest::addAuthenticationInfoTrailer(HttpReply *, int) STUB
void Auth::UserRequest::releaseAuthServer() STUB
const char * Auth::UserRequest::connLastHeader() STUB_RETVAL("stub")
AuthAclState Auth::UserRequest::authenticate(Auth::UserRequest::Pointer *, Http::HdrType, HttpRequest *, ConnStateData *, Ip::Address &, AccessLogEntry::Pointer &) STUB_RETVAL(AUTH_AUTHENTICATED)
AuthAclState Auth::UserRequest::tryToAuthenticateAndSetAuthUser(Auth::UserRequest::Pointer *, Http::HdrType, HttpRequest *, ConnStateData *, Ip::Address &, AccessLogEntry::Pointer &) STUB_RETVAL(AUTH_AUTHENTICATED)
void Auth::UserRequest::AddReplyAuthHeader(HttpReply *, Auth::UserRequest::Pointer, HttpRequest *, int, int) STUB
Auth::Scheme::Pointer Auth::UserRequest::scheme() const STUB_RETVAL(NULL)

#include "AuthReg.h"
void Auth::Init() STUB_NOP

#endif /* USE_AUTH */

