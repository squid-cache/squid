#define STUB_API "auth/libauth.la"

#include "STUB.h"
#include "squid.h"

#include "auth/Config.h"
Auth::UserRequest::Pointer Auth::Config::CreateAuthUser(const char *) STUB
Auth::Config * Auth::Config::Find(const char *) STUB
void Auth::Config::registerWithCacheManager(void) STUB_NOP

#include "auth/Gadgets.h"
int authenticateActiveSchemeCount(void) STUB
int authenticateSchemeCount(void) STUB
void authenticateInit(Auth::ConfigVector *) STUB
void authenticateRotate(void) STUB
void authenticateReset(void) STUB

AuthUserHashPointer::AuthUserHashPointer(Auth::User::Pointer anAuth_user) STUB
Auth::User::Pointer AuthUserHashPointer::user() const STUB

#include "auth/Scheme.h"
/* TODO: Fill in */

#include "auth/User.h"
Auth::User::User(Auth::Config *) STUB
Auth::CredentialState Auth::User::credentials() const STUB
void Auth::User::credentials(CredentialState) STUB
void Auth::User::absorb(Auth::User::Pointer) STUB
Auth::User::~User() STUB_NOP
void Auth::User::cacheInit(void) STUB
void Auth::User::CachedACLsReset() STUB
void Auth::User::cacheCleanup(void *) STUB
void Auth::User::clearIp() STUB
void Auth::User::removeIp(Ip::Address) STUB
void Auth::User::addIp(Ip::Address) STUB
void Auth::User::addToNameCache() STUB
void Auth::User::UsernameCacheStats(StoreEntry *) STUB

#include "auth/UserRequest.h"
void Auth::UserRequest::start(AUTHCB *, void *) STUB
bool Auth::UserRequest::valid() const STUB
void * Auth::UserRequest::operator new (size_t) STUB
void Auth::UserRequest::operator delete (void *) STUB
Auth::UserRequest::UserRequest() STUB
Auth::UserRequest::~UserRequest() STUB
void Auth::UserRequest::setDenyMessage(char const *) STUB
char const * Auth::UserRequest::getDenyMessage() STUB_RETVAL("stub")
char const * Auth::UserRequest::denyMessage(char const * const) STUB_RETVAL("stub")
void authenticateAuthUserRequestRemoveIp(Auth::UserRequest::Pointer, Ip::Address const &) STUB
void authenticateAuthUserRequestClearIp(Auth::UserRequest::Pointer) STUB
int authenticateAuthUserRequestIPCount(Auth::UserRequest::Pointer) STUB
int authenticateUserAuthenticated(Auth::UserRequest::Pointer) STUB
Auth::Direction Auth::UserRequest::direction() STUB
void Auth::UserRequest::addAuthenticationInfoHeader(HttpReply *, int) STUB
void Auth::UserRequest::addAuthenticationInfoTrailer(HttpReply *, int) STUB
void Auth::UserRequest::releaseAuthServer() STUB
const char * Auth::UserRequest::connLastHeader() STUB
AuthAclState Auth::UserRequest::authenticate(Auth::UserRequest::Pointer *, http_hdr_type, HttpRequest *, ConnStateData *, Ip::Address &) STUB
AuthAclState Auth::UserRequest::tryToAuthenticateAndSetAuthUser(Auth::UserRequest::Pointer *, http_hdr_type, HttpRequest *, ConnStateData *, Ip::Address &) STUB
void Auth::UserRequest::addReplyAuthHeader(HttpReply *, Auth::UserRequest::Pointer, HttpRequest *, int, int) STUB
void authenticateFixHeader(HttpReply *, Auth::UserRequest::Pointer, HttpRequest *, int, int) STUB
void authenticateAddTrailer(HttpReply *, Auth::UserRequest::Pointer, HttpRequest *, int) STUB
Auth::Scheme::Pointer Auth::UserRequest::scheme() const STUB

