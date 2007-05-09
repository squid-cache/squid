
/*
 * $Id: AuthUserRequest.h,v 1.6 2007/05/09 09:07:38 wessels Exp $
 *
 * DO NOT MODIFY NEXT 2 LINES:
 * arch-tag: 674533af-8b21-4641-b71a-74c4639072a0
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

#ifndef SQUID_AUTHUSERREQUEST_H
#define SQUID_AUTHUSERREQUEST_H

#include "client_side.h"

class AuthUser;

class ConnStateData;

class AuthScheme;

struct AuthUserIP
{
    dlink_node node;
    /* IP addr this user authenticated from */

    struct IN_ADDR ipaddr;
    time_t ip_expiretime;
};

class AuthUserRequest
{

public:
    /* this is the object passed around by client_side and acl functions */
    /* it has request specific data, and links to user specific data */
    /* the user */
    auth_user_t *_auth_user;

    int direction();
    virtual int authenticated() const = 0;
    virtual void authenticate(HttpRequest * request, ConnStateData::Pointer conn, http_hdr_type type) = 0;
    /* template method */
    virtual int module_direction() = 0;
    virtual void addHeader(HttpReply * rep, int accel);
    virtual void addTrailer(HttpReply * rep, int accel);
    virtual void onConnectionClose(ConnStateData *);
    /* template method */
    virtual void module_start(RH *, void *) = 0;
    virtual AuthUser *user() {return _auth_user;}

    virtual const AuthUser *user() const {return _auth_user;}

    virtual void user (AuthUser *aUser) {_auth_user=aUser;}

    static auth_acl_t tryToAuthenticateAndSetAuthUser(AuthUserRequest **, http_hdr_type, HttpRequest *, ConnStateData::Pointer, struct IN_ADDR);
    static void addReplyAuthHeader(HttpReply * rep, AuthUserRequest * auth_user_request, HttpRequest * request, int accelerated, int internal);

    AuthUserRequest();

    virtual ~AuthUserRequest();
    void *operator new (size_t byteCount);
    void operator delete (void *address);

    void start ( RH * handler, void *data);
    char const * denyMessage (char const * const default_message = NULL);
    /* these two are possibly overrideable in future */
    void setDenyMessage (char const *);
    char const * getDenyMessage ();

    size_t refCount() const;
    void _lock ();		// please use AUTHUSERREQUESTLOCK()
    void _unlock ();		// please use AUTHUSERREQUESTUNLOCK()

    char const *username() const;

    AuthScheme *scheme() const;

    virtual const char * connLastHeader();

private:

    static auth_acl_t authenticate(AuthUserRequest ** auth_user_request, http_hdr_type headertype, HttpRequest * request, ConnStateData::Pointer conn, struct IN_ADDR src_addr);

    /* return a message on the 407 error pages */
    char *message;

    /* how many 'processes' are working on this data */
    size_t references;

    /* We only attempt authentication once per http request. This
     * is to allow multiple auth acl references from different _access areas
     * when using connection based authentication
     */
    auth_acl_t lastReply;
};

/* AuthUserRequest */
extern size_t authenticateRequestRefCount (AuthUserRequest *);

extern void authenticateFixHeader(HttpReply *, AuthUserRequest *, HttpRequest *, int, int);
extern void authenticateAddTrailer(HttpReply *, AuthUserRequest *, HttpRequest *, int);

extern void authenticateAuthUserRequestRemoveIp(AuthUserRequest *, struct IN_ADDR);
extern void authenticateAuthUserRequestClearIp(AuthUserRequest *);
extern int authenticateAuthUserRequestIPCount(AuthUserRequest *);
extern int authenticateDirection(AuthUserRequest *);

extern int authenticateUserAuthenticated(AuthUserRequest *);
extern int authenticateValidateUser(AuthUserRequest *);

#if 0
#define AUTHUSERREQUESTUNLOCK(a,b) if(a){(a)->_unlock();debugs(0,0,HERE << "auth_user_request " << a << " was unlocked for " << b); (a)=NULL;}
#define AUTHUSERREQUESTLOCK(a,b) { (a)->_lock(); debugs(0,0,HERE << "auth_user_request " << a << " was locked for " << b); }
#endif
#define AUTHUSERREQUESTUNLOCK(a,b) if(a){(a)->_unlock();(a)=NULL;}
#define AUTHUSERREQUESTLOCK(a,b) (a)->_lock()


#endif /* SQUID_AUTHUSERREQUEST_H */
