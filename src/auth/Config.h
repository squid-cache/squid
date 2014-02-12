/*
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
#ifndef SQUID_AUTH_CONFIG_H
#define SQUID_AUTH_CONFIG_H

#if USE_AUTH

#include "auth/UserRequest.h"
#include "HelperChildConfig.h"

class StoreEntry;
class HttpReply;
class HttpRequest;
class wordlist;

/* for http_hdr_type parameters-by-value */
#include "HttpHeader.h"

namespace Auth
{

/**
 * \ingroup AuthAPI
 * \par
 * I am the configuration for an auth scheme.
 * Currently each scheme has only one instance of me,
 * but this may change.
 * \par
 * This class is treated like a ref counted class.
 * If the children ever stop being singletons, implement the
 * ref counting...
 */
class Config
{

public:
    static UserRequest::Pointer CreateAuthUser(const char *proxy_auth);

    static Config *Find(const char *proxy_auth);
    Config() : authenticateChildren(20), authenticateProgram(NULL) {}

    virtual ~Config() {}

    /**
     * Used by squid to determine whether the auth module has successfully initialised itself with the current configuration.
     *
     \retval true	Authentication Module loaded and running.
     \retval false	No Authentication Module loaded.
     */
    virtual bool active() const = 0;

    /**
     * new decode API: virtual factory pattern
     \par
     * Responsible for decoding the passed authentication header, creating or
     * linking to a AuthUser object and for storing any needed details to complete
     * authentication in Auth::UserRequest::authenticate().
     *
     \param proxy_auth	Login Pattern to parse.
     \retval *		Details needed to authenticate.
     */
    virtual UserRequest::Pointer decode(char const *proxy_auth) = 0;

    /**
     * squid is finished with this config, release any unneeded resources.
     * If a singleton, delete will not occur. if not a singleton (future),
     * delete will occur when no references are held.
     *
     \todo we need a 'done for reconfigure' and a 'done permanently' concept.
     */
    virtual void done() = 0;

    /**
     * The configured function is used to see if the auth module has been given valid
     * parameters and is able to handle authentication requests.
     *
     \retval true	Authentication Module configured ready for use.
     \retval false	Not configured or Configuration Error.
     *			No other module functions except Shutdown/Dump/Parse/FreeConfig will be called by Squid.
     */
    virtual bool configured() const = 0;

    /**
     * Shutdown just the auth helpers.
     * For use by log rotate etc. where auth needs to stay running, with the helpers restarted.
     */
    virtual void rotateHelpers(void) = 0;

    /**
     * Responsible for writing to the StoreEntry the configuration parameters that a user
     * would put in a config file to recreate the running configuration.
     */
    virtual void dump(StoreEntry *, const char *, Config *) = 0;

    /** add headers as needed when challenging for auth */
    virtual void fixHeader(UserRequest::Pointer, HttpReply *, http_hdr_type, HttpRequest *) = 0;

    /// Find any existing user credentials in the authentication cache by name and type.
    virtual Auth::User::Pointer findUserInCache(const char *nameKey, Auth::Type type);

    /** prepare to handle requests */
    virtual void init(Config *) = 0;

    /** expose any/all statistics to a CacheManager */
    virtual void registerWithCacheManager(void);

    /** parse config options */
    virtual void parse(Config *, int, char *) = 0;

    /** the http string id */
    virtual const char * type() const = 0;

public:
    HelperChildConfig authenticateChildren;
    wordlist *authenticateProgram; ///< Helper program to run, includes all parameters
};

typedef Vector<Config *> ConfigVector;

extern ConfigVector TheConfig;

} // namespace Auth

#endif /* USE_AUTH */
#endif /* SQUID_AUTHCONFIG_H */
