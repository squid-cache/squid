/*
 * $Id: ACLCertificateData.cc,v 1.9 2006/04/23 14:28:06 serassio Exp $
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
#include "ACLCertificateData.h"
#include "authenticate.h"
#include "ACLChecklist.h"
#include "wordlist.h"

ACLCertificateData::ACLCertificateData(SSLGETATTRIBUTE *sslStrategy) : attribute (NULL), values (), sslAttributeCall (sslStrategy)
{}

ACLCertificateData::ACLCertificateData(ACLCertificateData const &old) : attribute (NULL), values (old.values), sslAttributeCall (old.sslAttributeCall)
{
    if (old.attribute)
        attribute = xstrdup (old.attribute);
}

template<class T>
inline void
xRefFree(T &thing)
{
    xfree (thing);
}

ACLCertificateData::~ACLCertificateData()
{
    safe_free (attribute);
}

template<class T>
inline int
splaystrcmp (T&l, T&r)
{
    return strcmp ((char *)l,(char *)r);
}

bool
ACLCertificateData::match(SSL *ssl)
{
    if (!ssl)
        return 0;

    char const *value = sslAttributeCall(ssl, attribute);

    if (value == NULL)
        return 0;

    return values.match(value);
}

static void
aclDumpAttributeListWalkee(char * const & node_data, void *outlist)
{
    /* outlist is really a wordlist ** */
    wordlistAdd((wordlist **)outlist, node_data);
}

wordlist *
ACLCertificateData::dump()
{
    wordlist *wl = NULL;
    wordlistAdd(&wl, attribute);
    /* damn this is VERY inefficient for long ACL lists... filling
     * a wordlist this way costs Sum(1,N) iterations. For instance
     * a 1000-elements list will be filled in 499500 iterations.
     */
    /* XXX FIXME: don't break abstraction */
    values.values->walk(aclDumpAttributeListWalkee, &wl);
    return wl;
}

void
ACLCertificateData::parse()
{
    char *newAttribute = strtokFile();

    if (!newAttribute)
        self_destruct();

    /* an acl must use consistent attributes in all config lines */
    if (attribute) {
        if (strcasecmp(newAttribute, attribute) != 0)
            self_destruct();
    } else
        attribute = xstrdup(newAttribute);

    values.parse();
}

bool
ACLCertificateData::empty() const
{
    return values.empty();
}

ACLData<SSL *> *
ACLCertificateData::clone() const
{
    /* Splay trees don't clone yet. */
    return new ACLCertificateData(*this);
}
