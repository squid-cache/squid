
/*
 * $Id$
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

struct AuthUserIP {
    dlink_node node;
    /* IP addr this user authenticated from */

    IpAddress ipaddr;
    time_t ip_expiretime;
};

/**
 \ingroup AuthAPI
 * This is a short lived structure is the visible aspect of the authentication framework.
 */
class AuthUserRequest
{

public:
    /**
     * This is the object passed around by client_side and acl functions
     * it has request specific data, and links to user specific data
     * the user
     */
    AuthUser *_auth_user;

    /**
     *  Used by squid to determine what the next step in performing authentication for a given scheme is.
     *
     \retval -2	ERROR in the auth module. Cannot determine request direction.
     \retval -1	The auth module needs to send data to an external helper.
     *		Squid will prepare for a callback on the request and call the AUTHSSTART function.
     \retval  0	The auth module has all the information it needs to perform the authentication and provide a succeed/fail result.
     \retval  1	The auth module needs to send a new challenge to the request originator.
     *		Squid will return the appropriate status code (401 or 407) and call the registered FixError function to allow the auth module to insert it's challenge.
     */
    int direction();

    /**
     * Used by squid to determine whether the auth scheme has successfully authenticated the user request.
     *
     \retval true	User has successfully been authenticated.
     \retval false	Timeouts on cached credentials have occurred or for any reason the credentials are not valid.
     */
    virtual int authenticated() const = 0;
    virtual void authenticate(HttpRequest * request, ConnStateData * conn, http_hdr_type type) = 0;
    /* template method */
    virtual int module_direction() = 0;
    virtual void addHeader(HttpReply * rep, int accel);
    virtual void addTrailer(HttpReply * rep, int accel);
    virtual void onConnectionClose(ConnStateData *);

    /**
     * Called when squid is ready to put the request on hold and wait for a callback from the auth module
     * when the auth module has performed it's external activities.
     *
     \param handler	Handler to process the callback when its run
     \param data	CBDATA for handler
     */
    virtual void module_start(RH *handler, void *data) = 0;

    virtual AuthUser *user() {return _auth_user;}

    virtual const AuthUser *user() const {return _auth_user;}

    virtual void user(AuthUser *aUser) {_auth_user=aUser;}

    static auth_acl_t tryToAuthenticateAndSetAuthUser(AuthUserRequest **, http_hdr_type, HttpRequest *, ConnStateData *, IpAddress &);
    static void addReplyAuthHeader(HttpReply * rep, AuthUserRequest * auth_user_request, HttpRequest * request, int accelerated, int internal);

    AuthUserRequest();

    virtual ~AuthUserRequest();
    void *operator new(size_t byteCount);
    void operator delete(void *address);

    void start( RH * handler, void *data);
    char const * denyMessage(char const * const default_message = NULL);

    /** Possibly overrideable in future */
    void setDenyMessage(char const *);

    /** Possibly overrideable in future */
    char const * getDenyMessage();

    size_t refCount() const;
    void _lock();            /**< \note please use AUTHUSERREQUESTLOCK()   */
    void _unlock();          /**< \note please use AUTHUSERREQUESTUNLOCK() */

    /**
     * Squid does not make assumptions about where the username is stored.
     * This function must return a pointer to a NULL terminated string to be used in logging the request.
     * The string should NOT be allocated each time this function is called.
     *
     \retval NULL	No username/usercode is known.
     \retval *		Null-terminated username string.
     */
    char const *username() const;

    AuthScheme *scheme() const;

    virtual const char * connLastHeader();

private:

    static auth_acl_t authenticate(AuthUserRequest ** auth_user_request, http_hdr_type headertype, HttpRequest * request, ConnStateData * conn, IpAddress &src_addr);

    /** return a message on the 407 error pages */
    char *message;

    /** how many 'processes' are working on this data */
    size_t references;

    /**
     * We only attempt authentication once per http request. This
     * is to allow multiple auth acl references from different _access areas
     * when using connection based authentication
     */
    auth_acl_t lastReply;
};

/* AuthUserRequest */

/**
 \ingroup AuthAPI
 \deprecated Use AuthUserRequest::refCount() instead.
 */
extern size_t authenticateRequestRefCount (AuthUserRequest *);

/// \ingroup AuthAPI
extern void authenticateFixHeader(HttpReply *, AuthUserRequest *, HttpRequest *, int, int);
/// \ingroup AuthAPI
extern void authenticateAddTrailer(HttpReply *, AuthUserRequest *, HttpRequest *, int);

/// \ingroup AuthAPI
extern void authenticateAuthUserRequestRemoveIp(AuthUserRequest *, IpAddress const &);
/// \ingroup AuthAPI
extern void authenticateAuthUserRequestClearIp(AuthUserRequest *);
/// \ingroup AuthAPI
extern int authenticateAuthUserRequestIPCount(AuthUserRequest *);
/// \ingroup AuthAPI
/// \deprecated Use AuthUserRequest::direction() instead.
extern int authenticateDirection(AuthUserRequest *);

/// \ingroup AuthAPI
/// See AuthUserRequest::authenticated()
extern int authenticateUserAuthenticated(AuthUserRequest *);
/// \ingroup AuthAPI
extern int authenticateValidateUser(AuthUserRequest *);

/// \todo Drop dead code? or make a debugging option.
#if 0
#define AUTHUSERREQUESTUNLOCK(a,b) if(a){(a)->_unlock();debugs(0,0,HERE << "auth_user_request " << a << " was unlocked for " << b); (a)=NULL;}
#define AUTHUSERREQUESTLOCK(a,b) { (a)->_lock(); debugs(0,0,HERE << "auth_user_request " << a << " was locked for " << b); }
#endif
#define AUTHUSERREQUESTUNLOCK(a,b) if(a){(a)->_unlock();(a)=NULL;}
#define AUTHUSERREQUESTLOCK(a,b) (a)->_lock()


#endif /* SQUID_AUTHUSERREQUEST_H */
