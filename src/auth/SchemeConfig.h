/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_AUTH_SCHEMECONFIG_H
#define SQUID_SRC_AUTH_SCHEMECONFIG_H

#if USE_AUTH

#include "AccessLogEntry.h"
#include "auth/forward.h"
#include "auth/UserRequest.h"
#include "helper/ChildConfig.h"

class StoreEntry;
class HttpReply;
class HttpRequest;
class wordlist;

/* for Http::HdrType parameters-by-value */
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
class SchemeConfig
{

public:
    static UserRequest::Pointer CreateAuthUser(const char *proxy_auth, AccessLogEntry::Pointer &al);

    static SchemeConfig *Find(const char *proxy_auth);
    /// Call this method if you need a guarantee that all auth schemes has been
    /// already configured.
    static SchemeConfig *GetParsed(const char *proxy_auth);
    SchemeConfig() : authenticateChildren(20) {}

    virtual ~SchemeConfig() {}

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
    virtual UserRequest::Pointer decode(char const *proxy_auth, const HttpRequest *request, const char *requestRealm) = 0;

    /**
     * squid is finished with this config, release any unneeded resources.
     * If a singleton, delete will not occur. if not a singleton (future),
     * delete will occur when no references are held.
     *
     * TODO: need a 'done for reconfigure' and a 'done permanently' concept.
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
    virtual bool dump(StoreEntry *, const char *, SchemeConfig *) const;

    /** add headers as needed when challenging for auth */
    virtual void fixHeader(UserRequest::Pointer, HttpReply *, Http::HdrType, HttpRequest *) = 0;

    /** prepare to handle requests */
    virtual void init(SchemeConfig *) = 0;

    /** expose any/all statistics to a CacheManager */
    virtual void registerWithCacheManager(void);

    /** parse config options */
    virtual void parse(SchemeConfig *, int, char *);

    /** the http string id */
    virtual const char * type() const = 0;

public:
    Helper::ChildConfig authenticateChildren;
    wordlist *authenticateProgram = nullptr; ///< Helper program to run, includes all parameters
    String keyExtrasLine;  ///< The format of the request to the auth helper
    Format::Format *keyExtras = nullptr; ///< The compiled request format
    int keep_alive = 1; ///< whether to close the connection on auth challenges. default: on
    int utf8 = 0; ///< wheter to accept UTF-8 characterset instead of ASCII. default: off

protected:
    /**
     * Parse Accept-Language header and return whether a CP1251 encoding
     * allowed or not.
     *
     * CP1251 (aka Windows-1251) is an 8-bit character encoding, designed
     * to cover languages that use the Cyrillic script.
     */
    bool isCP1251EncodingAllowed(const HttpRequest *request);

    /// RFC 7235 section 2.2 - Protection Space (Realm)
    SBuf realm;
};

} // namespace Auth

#endif /* USE_AUTH */
#endif /* SQUID_SRC_AUTH_SCHEMECONFIG_H */

