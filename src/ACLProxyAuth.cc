/*
 * $Id$
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
#include "ACLProxyAuth.h"
#include "authenticate.h"
#include "ACLChecklist.h"

MemPool *ACLProxyAuth::Pool(NULL);
void *
ACLProxyAuth::operator new (size_t byteCount)
{
    /* derived classes with different sizes must implement their own new */
    assert (byteCount == sizeof (ACLProxyAuth));
    if (!Pool)
	Pool = memPoolCreate("ACLProxyAuth", sizeof (ACLProxyAuth));
    return memPoolAlloc(Pool);
}

void
ACLProxyAuth::operator delete (void *address)
{
    memPoolFree (Pool, address);
}

void
ACLProxyAuth::deleteSelf() const
{
    delete this;
}

ACLProxyAuth::~ACLProxyAuth()
{
    delete data;
}

char const *
ACLProxyAuth::typeString() const
{
    return "proxy_auth";
}

void
ACLProxyAuth::parse()
{
    if (authenticateSchemeCount() == 0) {
	debug(28, 0) ("aclProxyAuth::parse: IGNORING: Proxy Auth ACL '%s' "
		      "because no authentication schemes were compiled.\n", cfgline);
    } else if (authenticateActiveSchemeCount() == 0) {
	debug(28, 0) ("aclProxyAuth::parse: IGNORING: Proxy Auth ACL '%s' "
		      "because no authentication schemes are fully configured.\n", cfgline);
    } else {
	debug(28, 3) ("aclParseUserList: current is null. Creating\n");
	data = new ACLUserData;
	data->parse();
    }
}

extern int
aclMatchProxyAuth(void *data, auth_user_request_t * auth_user_request,
    ACLChecklist * checklist, squid_acl acltype);
int
ACLProxyAuth::match(ACLChecklist *checklist)
{
    int ti;
    if ((ti = aclAuthenticated(checklist)) != 1)
	return ti;
    ti = aclMatchProxyAuth(data, checklist->auth_user_request,
			   checklist, aclType());
    checklist->auth_user_request = NULL;
    return ti;
}

wordlist *
ACLProxyAuth::dump() const
{
    return data->dump();
}

bool
ACLProxyAuth::valid () const
{
    return data != NULL;
}
