/*
 * $Id: ACLMaxUserIP.cc,v 1.11 2006/10/08 13:10:34 serassio Exp $
 *
 * DEBUG: section 28    Access Control
 * AUTHOR: Duane Wessels
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
 *
 * Copyright (c) 2003, Robert Collins <robertc@squid-cache.org>
 */

#include "squid.h"
#include "ACLMaxUserIP.h"
#include "AuthUserRequest.h"
#include "authenticate.h"
#include "wordlist.h"
#include "ConfigParser.h"

ACL::Prototype ACLMaxUserIP::RegistryProtoype(&ACLMaxUserIP::RegistryEntry_, "max_user_ip");

ACLMaxUserIP ACLMaxUserIP::RegistryEntry_("max_user_ip");

ACL *
ACLMaxUserIP::clone() const
{
    return new ACLMaxUserIP(*this);
}

ACLMaxUserIP::ACLMaxUserIP (char const *theClass) : class_ (theClass), maximum(0)
{}

ACLMaxUserIP::ACLMaxUserIP (ACLMaxUserIP const & old) :class_ (old.class_), maximum (old.maximum), flags (old.flags)
{}

ACLMaxUserIP::~ACLMaxUserIP()
{}

char const *
ACLMaxUserIP::typeString() const
{
    return class_;
}

bool
ACLMaxUserIP::empty () const
{
    return false;
}

bool
ACLMaxUserIP::valid () const
{
    return maximum > 0;
}

void
ACLMaxUserIP::parse()
{
    if (maximum) {
        debug(28, 1) ("Attempting to alter already set User max IP acl\n");
        return;
    }

    char *t = ConfigParser::strtokFile();

    if (!t)
        return;

    debug(28, 5) ("aclParseUserMaxIP: First token is %s\n", t);

    if (strcmp("-s", t) == 0) {
        debug(28, 5) ("aclParseUserMaxIP: Going strict\n");
        flags.strict = 1;
        t = ConfigParser::strtokFile();
    }

    if (!t)
        return;

    maximum = xatoi(t);

    debug(28, 5) ("aclParseUserMaxIP: Max IP address's %d\n", (int) maximum);

    return;
}

/*
 * aclMatchUserMaxIP - check for users logging in from multiple IP's 
 * 0 : No match
 * 1 : Match 
 */
int
ACLMaxUserIP::match(auth_user_request_t * auth_user_request,

                    struct IN_ADDR const &src_addr)
{
    /*
     * the logic for flush the ip list when the limit is hit vs keep
     * it sorted in most recent access order and just drop the oldest
     * one off is currently undecided (RBC)
     */

    if (authenticateAuthUserRequestIPCount(auth_user_request) <= maximum)
        return 0;

    debug(28, 1) ("aclMatchUserMaxIP: user '%s' tries to use too many IP addresses (max %d allowed)!\n", auth_user_request->username(), maximum);

    /* this is a match */
    if (flags.strict)
    {
        /*
         * simply deny access - the user name is already associated with
         * the request 
         */
        /* remove _this_ ip, as it is the culprit for going over the limit */
        authenticateAuthUserRequestRemoveIp(auth_user_request, src_addr);
        debug(28, 4) ("aclMatchUserMaxIP: Denying access in strict mode\n");
    } else
    {
        /*
         * non-strict - remove some/all of the cached entries 
         * ie to allow the user to move machines easily
         */
        authenticateAuthUserRequestClearIp(auth_user_request);
        debug(28, 4) ("aclMatchUserMaxIP: Denying access in non-strict mode - flushing the user ip cache\n");
    }

    return 1;
}

int
ACLMaxUserIP::match(ACLChecklist *checklist)
{
    int ti;

    if ((ti = checklist->authenticated()) != 1)
        return ti;

    ti = match(checklist->auth_user_request, checklist->src_addr);

    checklist->auth_user_request = NULL;

    return ti;
}

wordlist *
ACLMaxUserIP::dump() const
{
    if (!maximum)
        return NULL;

    wordlist *W = NULL;

    if (flags.strict)
        wordlistAdd(&W, "-s");

    char buf[128];

    snprintf(buf, sizeof(buf), "%lu", (unsigned long int) maximum);

    wordlistAdd(&W, buf);

    return W;
}
