
/*
 * $Id: authenticate.h,v 1.10 2003/07/12 12:39:56 robertc Exp $
 *
 *
 * SQUID Web Proxy Cache          http://www.squid-cache.org/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from
 *  the Internet community; see the CONTRIBUTORS file for full
 *  details.   Many organizations have provided support for Squid's
 *  development; see the SPONSORS file for full details.  Squid is
 *  Copyrighted (C) 2001 by the Regents of the University of
 *  California; see the COPYRIGHT file for full details.  Squid
 *  incorporates software developed and/or copyrighted by other
 *  sources; see the CREDITS file for full details.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *  
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *  
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111, USA.
 *
 */

#ifndef SQUID_AUTHENTICATE_H
#define SQUID_AUTHENTICATE_H

#include "client_side.h"

class AuthUser;

struct AuthUserHashPointer : public hash_link
{
    /* first two items must be same as hash_link */

public:
    static void removeFromCache (void *anAuthUserHashPointer);

    AuthUserHashPointer (AuthUser *);

    void *operator new (size_t byteCount);
    void operator delete (void *address);
    AuthUser *user() const;

private:
    static MemPool *pool;

    AuthUser *auth_user;
};

struct AuthUserIP
{
    dlink_node node;
    /* IP addr this user authenticated from */

    struct in_addr ipaddr;
    time_t ip_expiretime;
};

class AuthUser
{

public:
    /* extra fields for proxy_auth */
    /* this determines what scheme owns the user data. */
    auth_type_t auth_type;
    /* the index +1 in the authscheme_list to the authscheme entry */
    int auth_module;
    /* we only have one username associated with a given auth_user struct */
    auth_user_hash_pointer *usernamehash;
    /* we may have many proxy-authenticate strings that decode to the same user */
    dlink_list proxy_auth_list;
    dlink_list proxy_match_cache;
    /* what ip addresses has this user been seen at?, plus a list length cache */
    dlink_list ip_list;
    size_t ipcount;
    long expiretime;
    /* how many references are outstanding to this instance */
    size_t references;
    /* the auth scheme has it's own private data area */
    void *scheme_data;
    /* the auth_user_request structures that link to this. Yes it could be a splaytree
     * but how many requests will a single username have in parallel? */
    dlink_list requests;

public:
    static void cacheInit ();
    static void CachedACLsReset();

    void absorb(auth_user_t *from);
    AuthUser (const char *);
    ~AuthUser ();
    void *operator new (size_t byteCount);
    void operator delete (void *address);
    char const *username() const;

private:
    static void cacheCleanup (void *unused);
    static MemPool *pool;
};

/* Per scheme request data ABC */

class AuthUserRequestState
{

public:
    void *operator new (size_t);
    void operator delete (void *);
    virtual void deleteSelf() const = 0;
    virtual ~AuthUserRequestState(){}

    virtual int authenticated() const = 0;
    virtual void authenticate(request_t * request, ConnStateData::Pointer conn, http_hdr_type type) = 0;
    virtual int direction() = 0;
    virtual void addHeader(HttpReply * rep, int accel) {}}

;

class AuthUserRequest
{

public:
    /* this is the object passed around by client_side and acl functions */
    /* it has request specific data, and links to user specific data */
    /* the user */
    auth_user_t *auth_user;
    AuthUserRequestState *state() const { return state_;}

    void state( AuthUserRequestState *aState) {assert ((!state() && aState) || (state() && !aState)); state_ = aState;}

public:

    static auth_acl_t tryToAuthenticateAndSetAuthUser(auth_user_request_t **, http_hdr_type, request_t *, ConnStateData::Pointer, struct in_addr);
    static void addReplyAuthHeader(HttpReply * rep, auth_user_request_t * auth_user_request, request_t * request, int accelerated, int internal);

    ~AuthUserRequest();
    void *operator new (size_t byteCount);
    void operator delete (void *address);
    void start ( RH * handler, void *data);
    void setDenyMessage (char const *);
    char const * getDenyMessage ();
    size_t refCount() const;

    void lock ()

        ;
    void unlock ();

    char const *username() const;

private:

    static auth_acl_t authenticate(auth_user_request_t ** auth_user_request, http_hdr_type headertype, request_t * request, ConnStateData::Pointer conn, struct in_addr src_addr);

    static auth_user_request_t *createAuthUser (const char *proxy_auth);

    static MemPool *pool;

    AuthUserRequest();

    void decodeAuth (const char *proxy_auth);

    /* return a message on the 407 error pages */
    char *message;

    /* how many 'processes' are working on this data */
    size_t references;

    /* We only attempt authentication once per http request. This
     * is to allow multiple auth acl references from different _access areas
     * when using connection based authentication
     */
    auth_acl_t lastReply;

    AuthUserRequestState *state_;
};

/* authenticate.c authenticate scheme routines typedefs */
typedef int AUTHSACTIVE(void);
typedef int AUTHSAUTHED(auth_user_request_t *);
typedef void AUTHSAUTHUSER(auth_user_request_t *, request_t *, ConnStateData::Pointer, http_hdr_type);
typedef int AUTHSCONFIGURED(void);
typedef void AUTHSDECODE(auth_user_request_t *, const char *);
typedef int AUTHSDIRECTION(auth_user_request_t *);
typedef void AUTHSDUMP(StoreEntry *, const char *, authScheme *);
typedef void AUTHSFIXERR(auth_user_request_t *, HttpReply *, http_hdr_type, request_t *);
typedef void AUTHSADDTRAILER(auth_user_request_t *, HttpReply *, int);
typedef void AUTHSFREE(auth_user_t *);
typedef void AUTHSFREECONFIG(authScheme *);
typedef char const *AUTHSUSERNAME(auth_user_t const *);
typedef void AUTHSONCLOSEC(ConnStateData *);
typedef void AUTHSPARSE(authScheme *, int, char *);
typedef void AUTHSINIT(authScheme *);
typedef void AUTHSREQFREE(auth_user_request_t *);
typedef void AUTHSSETUP(authscheme_entry_t *);
typedef void AUTHSSHUTDOWN(void);
typedef void AUTHSSTART(auth_user_request_t *, RH *, void *);
typedef void AUTHSSTATS(StoreEntry *);
typedef const char *AUTHSCONNLASTHEADER(auth_user_request_t *);

/* subsumed by the C++ interface */
extern void authenticateAuthUserMerge(auth_user_t *, auth_user_t *);
extern auth_user_t *authenticateAuthUserNew(const char *);

/* AuthUserRequest */
extern void authenticateStart(auth_user_request_t *, RH *, void *);

extern auth_acl_t authenticateTryToAuthenticateAndSetAuthUser(auth_user_request_t **, http_hdr_type, request_t *, ConnStateData::Pointer, struct in_addr);
extern void authenticateSetDenyMessage (auth_user_request_t *, char const *);
extern size_t authenticateRequestRefCount (auth_user_request_t *);
extern char const *authenticateAuthUserRequestMessage(auth_user_request_t *);

extern int authenticateAuthSchemeId(const char *typestr);
extern void authenticateSchemeInit(void);
extern void authenticateInit(authConfig *);
extern void authenticateShutdown(void);
extern void authenticateFixHeader(HttpReply *, auth_user_request_t *, request_t *, int, int);
extern void authenticateAddTrailer(HttpReply *, auth_user_request_t *, request_t *, int);
extern void authenticateAuthUserUnlock(auth_user_t * auth_user);
extern void authenticateAuthUserLock(auth_user_t * auth_user);
extern void authenticateAuthUserRequestUnlock(auth_user_request_t *);
extern void authenticateAuthUserRequestLock(auth_user_request_t *);
extern int authenticateAuthUserInuse(auth_user_t * auth_user);

extern void authenticateAuthUserRequestRemoveIp(auth_user_request_t *, struct in_addr);
extern void authenticateAuthUserRequestClearIp(auth_user_request_t *);
extern size_t authenticateAuthUserRequestIPCount(auth_user_request_t *);
extern int authenticateDirection(auth_user_request_t *);
extern void authenticateFreeProxyAuthUserACLResults(void *data);
extern int authenticateActiveSchemeCount(void);
extern int authenticateSchemeCount(void);
extern void authenticateUserNameCacheAdd(auth_user_t * auth_user);

extern int authenticateCheckAuthUserIP(struct in_addr request_src_addr, auth_user_request_t * auth_user);
extern int authenticateUserAuthenticated(auth_user_request_t *);
extern void authenticateUserCacheRestart(void);
extern char const *authenticateUserRequestUsername(auth_user_request_t *);
extern int authenticateValidateUser(auth_user_request_t *);
extern void authenticateOnCloseConnection(ConnStateData * conn);
extern void authSchemeAdd(const char *type, AUTHSSETUP * setup);

/* AuthUserHashPointer */
extern auth_user_t* authUserHashPointerUser(auth_user_hash_pointer *);

/* auth_modules.c */
SQUIDCEXTERN void authSchemeSetup(void);

/*
 * This defines an auth scheme module
 */

struct _authscheme_entry
{
    const char *typestr;
    AUTHSACTIVE *Active;
    AUTHSADDTRAILER *AddTrailer;
    AUTHSAUTHED *authenticated;
    AUTHSAUTHUSER *authAuthenticate;
    AUTHSCONFIGURED *configured;
    AUTHSDUMP *dump;
    AUTHSFIXERR *authFixHeader;
    AUTHSFREE *FreeUser;
    AUTHSFREECONFIG *freeconfig;
    AUTHSUSERNAME *authUserUsername;
    AUTHSONCLOSEC *oncloseconnection;   /*optional */
    AUTHSCONNLASTHEADER *authConnLastHeader;
    AUTHSDECODE *decodeauth;
    AUTHSDIRECTION *getdirection;
    AUTHSPARSE *parse;
    AUTHSINIT *init;
    AUTHSREQFREE *requestFree;
    AUTHSSHUTDOWN *donefunc;
    AUTHSSTART *authStart;
    AUTHSSTATS *authStats;
};

/*
 * This is a configured auth scheme
 */

/* private data types */

struct _authScheme
{
    /* pointer to the authscheme_list's string entry */
    const char *typestr;
    /* the scheme id in the authscheme_list */
    int Id;
    /* the scheme's configuration details. */
    void *scheme_data;
};

#endif /* SQUID_AUTHENTICATE_H */
