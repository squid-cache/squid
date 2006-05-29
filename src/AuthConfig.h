
/*
 * $Id: AuthConfig.h,v 1.2 2006/05/29 00:14:59 robertc Exp $
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

#ifndef SQUID_AUTHCONFIG_H
#define SQUID_AUTHCONFIG_H

/*
 * I am the configuration for an auth scheme.
 * Currently each scheme has only one instance of me,
 * but this may change.
 */

/* This class is treated like a ref counted class.
 * If the children ever stop being singletons, implement the
 * ref counting...
 */

class AuthConfig
{

public:
    static AuthUserRequest *CreateAuthUser (const char *proxy_auth);

    static AuthConfig *Find(const char *proxy_auth);
    AuthConfig() {}

    virtual ~AuthConfig(){}

    /* Is this configuration active? (helpers running etc etc */
    virtual bool active() const = 0;
    /* new decode API: virtual factory pattern */
    virtual AuthUserRequest *decode(char const *proxy_auth) = 0;
    /* squid is finished with this config, release any unneeded resources.
     * If a singleton, delete will not occur. if not a singleton (future),
     * delete will occur when no references are held.
     * TODO: we need a 'done for reconfigure' and a 'done permanently' concept.
     */
    virtual void done() = 0;
    /* is this config complete enough to run */
    virtual bool configured() const = 0;
    /* output the parameters */
    virtual void dump(StoreEntry *, const char *, AuthConfig *) = 0;
    /* add headers as needed when challenging for auth */
    virtual void fixHeader(auth_user_request_t *, HttpReply *, http_hdr_type, HttpRequest *) = 0;
    /* prepare to handle requests */
    virtual void init(AuthConfig *) = 0;
    /* expose any/all statistics to a CacheManager */
    virtual void registerWithCacheManager(CacheManager & manager);
    /* parse config options */
    virtual void parse(AuthConfig *, int, char *) = 0;
    /* the http string id */
    virtual const char * type() const = 0;
};

#endif /* SQUID_AUTHCONFIG_H */
