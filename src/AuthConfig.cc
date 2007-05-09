
/*
 * $Id: AuthConfig.cc,v 1.4 2007/05/09 09:07:38 wessels Exp $
 *
 * DEBUG: section 29    Authenticator
 * AUTHOR:  Robert Collins
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

#include "squid.h"
#include "AuthConfig.h"
#include "AuthUserRequest.h"

/* Get Auth User: Return a filled out auth_user structure for the given
 * Proxy Auth (or Auth) header. It may be a cached Auth User or a new
 * Unauthenticated structure. The structure is given an inital lock here.
 * It may also be NULL reflecting that no user could be created.
 */
AuthUserRequest *
AuthConfig::CreateAuthUser(const char *proxy_auth)
{
    assert(proxy_auth != NULL);
    debugs(29, 9, "AuthConfig::CreateAuthUser: header = '" << proxy_auth << "'");

    AuthConfig *config = Find(proxy_auth);

    if (config == NULL || !config->active()) {
        debugs(29, 1, "AuthConfig::CreateAuthUser: Unsupported or unconfigured/inactive proxy-auth scheme, '" << proxy_auth << "'");
        return NULL;
    }

    AuthUserRequest *result = config->decode (proxy_auth);

    /*
     * DPW 2007-05-08
     * Do not lock the AuthUserRequest on the caller's behalf.
     * Callers must manage their own locks.
     */
    return result;
}

AuthConfig *
AuthConfig::Find(const char *proxy_auth)
{
    for (authConfig::iterator  i = Config.authConfiguration.begin(); i != Config.authConfiguration.end(); ++i)
        if (strncasecmp(proxy_auth, (*i)->type(), strlen((*i)->type())) == 0)
            return *i;

    return NULL;
}

/* Default behaviour is to expose nothing */
void
AuthConfig::registerWithCacheManager(CacheManager & manager)
{}
