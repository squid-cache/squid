/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_AUTH_CONFIG_H
#define SQUID_AUTH_CONFIG_H

#if USE_AUTH

#include "AccessLogEntry.h"
#include "auth/UserRequest.h"
#include "helper/ChildConfig.h"

class StoreEntry;
class HttpReply;
class HttpRequest;
class wordlist;

/* for http_hdr_type parameters-by-value */
#include "HttpHeader.h"

namespace Format
{
class Format;
}

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
    static UserRequest::Pointer CreateAuthUser(const char *proxy_auth, AccessLogEntry::Pointer &al);

    static Config *Find(const char *proxy_auth);
    Config() : authenticateChildren(20), authenticateProgram(NULL), keyExtras(NULL) {}

    virtual ~Config() {}

    /**
     * Used by squid to determine whether the auth module has successfully initialised itself with the current configuration.
     *
     \retval true   Authentication Module loaded and running.
     \retval false  No Authentication Module loaded.
     */
    virtual bool active() const = 0;

    /**
     * new decode API: virtual factory pattern
     \par
     * Responsible for decoding the passed authentication header, creating or
     * linking to a AuthUser object and for storing any needed details to complete
     * authentication in Auth::UserRequest::authenticate().
     *
     \param proxy_auth  Login Pattern to parse.
     \retval *      Details needed to authenticate.
     */
    virtual UserRequest::Pointer decode(char const *proxy_auth, const char *requestRealm) = 0;

    /**
     * squid is finished with this config, release any unneeded resources.
     * If a singleton, delete will not occur. if not a singleton (future),
     * delete will occur when no references are held.
     *
     \todo we need a 'done for reconfigure' and a 'done permanently' concept.
     */
    virtual void done();

    /**
     * The configured function is used to see if the auth module has been given valid
     * parameters and is able to handle authentication requests.
     *
     \retval true   Authentication Module configured ready for use.
     \retval false  Not configured or Configuration Error.
     *          No other module functions except Shutdown/Dump/Parse/FreeConfig will be called by Squid.
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
     * Returns whether the scheme is configured.
     */
    virtual bool dump(StoreEntry *, const char *, Config *) const;

    /** add headers as needed when challenging for auth */
    virtual void fixHeader(UserRequest::Pointer, HttpReply *, http_hdr_type, HttpRequest *) = 0;

    /// Find any existing user credentials in the authentication cache by name and type.
    virtual Auth::User::Pointer findUserInCache(const char *nameKey, Auth::Type type);

    /** prepare to handle requests */
    virtual void init(Config *) = 0;

    /** expose any/all statistics to a CacheManager */
    virtual void registerWithCacheManager(void);

    /** parse config options */
    virtual void parse(Config *, int, char *);

    /** the http string id */
    virtual const char * type() const = 0;

public:
    Helper::ChildConfig authenticateChildren;
    wordlist *authenticateProgram; ///< Helper program to run, includes all parameters
    String keyExtrasLine;  ///< The format of the request to the auth helper
    Format::Format *keyExtras; ///< The compiled request format

protected:
    /// RFC 7235 section 2.2 - Protection Space (Realm)
    SBuf realm;
};

typedef std::vector<Config *> ConfigVector;

extern ConfigVector TheConfig;

} // namespace Auth

#endif /* USE_AUTH */
#endif /* SQUID_AUTHCONFIG_H */

