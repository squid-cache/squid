/*
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

#ifndef SQUID_AUTH_USERREQUEST_H
#define SQUID_AUTH_USERREQUEST_H

#if USE_AUTH

#include "auth/AuthAclState.h"
#include "auth/Scheme.h"
#include "auth/User.h"
#include "dlink.h"
#include "ip/Address.h"
#include "typedefs.h"
#include "HttpHeader.h"

class ConnStateData;
class HttpReply;
class HttpRequest;

/**
 * Maximum length (buffer size) for token strings.
 */
// AYJ: must match re-definition in helpers/negotiate_auth/kerberos/negotiate_kerb_auth.cc
#define MAX_AUTHTOKEN_LEN   32768

/// \ingroup AuthAPI
class AuthUserIP
{
public:
    dlink_node node;
    /* IP addr this user authenticated from */

    Ip::Address ipaddr;
    time_t ip_expiretime;
};

// TODO: make auth schedule AsyncCalls?
typedef void AUTHCB(void*);

namespace Auth
{

// NP: numeric values specified for old code backward compatibility.
//  remove after transition is complete
enum Direction {
    CRED_CHALLENGE = 1, ///< Client needs to be challenged. secure token.
    CRED_VALID = 0,     ///< Credentials are valid and a up to date. The OK/Failed state is accurate.
    CRED_LOOKUP = -1,   ///< Credentials need to be validated with the backend helper
    CRED_ERROR = -2     ///< ERROR in the auth module. Cannot determine the state of this request.
};

/**
 * This is a short lived structure is the visible aspect of the authentication framework.
 *
 * It and its children hold the state data while processing authentication for a client request.
 * The AuthenticationStateData object is merely a CBDATA wrapper for one of these.
 */
class UserRequest : public RefCountable
{
public:
    typedef RefCount<Auth::UserRequest> Pointer;

    UserRequest();
    virtual ~UserRequest();
    void *operator new(size_t byteCount);
    void operator delete(void *address);

public:
    /**
     * This is the object passed around by client_side and acl functions
     * it has request specific data, and links to user specific data
     * the user
     */
    User::Pointer _auth_user;

    /**
     *  Used by squid to determine what the next step in performing authentication for a given scheme is.
     *
     * \retval CRED_ERROR	ERROR in the auth module. Cannot determine request direction.
     * \retval CRED_LOOKUP	The auth module needs to send data to an external helper.
     *				Squid will prepare for a callback on the request and call the AUTHSSTART function.
     * \retval CRED_VALID	The auth module has all the information it needs to perform the authentication
     *				and provide a succeed/fail result.
     * \retval CRED_CHALLENGE	The auth module needs to send a new challenge to the request originator.
     *				Squid will return the appropriate status code (401 or 407) and call the registered
     *				FixError function to allow the auth module to insert it's challenge.
     */
    Direction direction();

    /**
     * Used by squid to determine whether the auth scheme has successfully authenticated the user request.
     *
     \retval true	User has successfully been authenticated.
     \retval false	Timeouts on cached credentials have occurred or for any reason the credentials are not valid.
     */
    virtual int authenticated() const = 0;

    /**
     * Check a auth_user pointer for validity.
     * Does not check passwords, just data sensability. Broken or Unknown auth_types are not valid for use...
     *
     * \retval false    User credentials are missing.
     * \retval false    User credentials use an unknown scheme type.
     * \retval false    User credentials are broken for their scheme.
     *
     * \retval true	User credentials exist and may be able to authenticate.
     */
    bool valid() const;

    virtual void authenticate(HttpRequest * request, ConnStateData * conn, http_hdr_type type) = 0;

    /* template method - what needs to be done next? advertise schemes, challenge, handle error, nothing? */
    virtual Direction module_direction() = 0;

    /* add the [Proxy-]Authentication-Info header */
    virtual void addAuthenticationInfoHeader(HttpReply * rep, int accel);

    /* add the [Proxy-]Authentication-Info trailer */
    virtual void addAuthenticationInfoTrailer(HttpReply * rep, int accel);

    virtual void onConnectionClose(ConnStateData *);

    /**
     * Called when squid is ready to put the request on hold and wait for a callback from the auth module
     * when the auth module has performed it's external activities.
     *
     * \param handler	Handler to process the callback when its run
     * \param data	CBDATA for handler
     */
    virtual void module_start(AUTHCB *handler, void *data) = 0;

    // User credentials object this UserRequest is managing
    virtual User::Pointer user() {return _auth_user;}
    virtual const User::Pointer user() const {return _auth_user;}
    virtual void user(User::Pointer aUser) {_auth_user=aUser;}

    /**
     * Locate user credentials in one of several locations. Begin authentication if needed.
     *
     * Credentials may be found in one of the following locations (listed by order of preference):
     * - the source passed as parameter aUR
     * - cached in the HttpRequest parameter from a previous authentication of this request
     * - cached in the ConnStateData paremeter from a previous authentication of this connection
     *   (only applies to some situations. ie NTLM, Negotiate, Kerberos auth schemes,
     *    or decrypted SSL requests from inside an authenticated CONNECT tunnel)
     * - cached in the user credentials cache from a previous authentication of the same credentials
     *   (only applies to cacheable authentication methods, ie Basic auth)
     * - new credentials created from HTTP headers in this request
     *
     * The found credentials are returned in aUR and if successfully authenticated
     * may now be cached in one or more of the above locations.
     *
     * \return Some AUTH_ACL_* state
     */
    static AuthAclState tryToAuthenticateAndSetAuthUser(UserRequest::Pointer *aUR, http_hdr_type, HttpRequest *, ConnStateData *, Ip::Address &);

    /// Add the appropriate [Proxy-]Authenticate header to the given reply
    static void addReplyAuthHeader(HttpReply * rep, UserRequest::Pointer auth_user_request, HttpRequest * request, int accelerated, int internal);

    void start(AUTHCB *handler, void *data);
    char const * denyMessage(char const * const default_message = NULL);

    /** Possibly overrideable in future */
    void setDenyMessage(char const *);

    /** Possibly overrideable in future */
    char const * getDenyMessage();

    /**
     * Squid does not make assumptions about where the username is stored.
     * This function must return a pointer to a NULL terminated string to be used in logging the request.
     * The string should NOT be allocated each time this function is called.
     *
     \retval NULL	No username/usercode is known.
     \retval *		Null-terminated username string.
     */
    char const *username() const;

    Scheme::Pointer scheme() const;

    virtual const char * connLastHeader();

private:

    static AuthAclState authenticate(UserRequest::Pointer * auth_user_request, http_hdr_type headertype, HttpRequest * request, ConnStateData * conn, Ip::Address &src_addr);

    /** return a message on the 407 error pages */
    char *message;

    /**
     * We only attempt authentication once per http request. This
     * is to allow multiple auth acl references from different _access areas
     * when using connection based authentication
     */
    AuthAclState lastReply;
};

} // namespace Auth

/* AuthUserRequest */

/// \ingroup AuthAPI
void authenticateFixHeader(HttpReply *, Auth::UserRequest::Pointer, HttpRequest *, int, int);
/// \ingroup AuthAPI
void authenticateAddTrailer(HttpReply *, Auth::UserRequest::Pointer, HttpRequest *, int);

/// \ingroup AuthAPI
void authenticateAuthUserRequestRemoveIp(Auth::UserRequest::Pointer, Ip::Address const &);
/// \ingroup AuthAPI
void authenticateAuthUserRequestClearIp(Auth::UserRequest::Pointer);
/// \ingroup AuthAPI
int authenticateAuthUserRequestIPCount(Auth::UserRequest::Pointer);

/// \ingroup AuthAPI
/// See Auth::UserRequest::authenticated()
int authenticateUserAuthenticated(Auth::UserRequest::Pointer);

#endif /* USE_AUTH */
#endif /* SQUID_AUTHUSERREQUEST_H */
