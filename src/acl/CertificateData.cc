/*
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
#include "acl/CertificateData.h"
#include "acl/Checklist.h"
#include "Debug.h"
#include "cache_cf.h"
#include "wordlist.h"

ACLCertificateData::ACLCertificateData(Ssl::GETX509ATTRIBUTE *sslStrategy, const char *attrs, bool optionalAttr) : validAttributesStr(attrs), attributeIsOptional(optionalAttr), attribute (NULL), values (), sslAttributeCall (sslStrategy)
{
    if (attrs) {
        size_t current = 0;
        size_t next = std::string::npos;
        std::string valid(attrs);
        do {
            next = valid.find_first_of( "|", current);
            validAttributes.push_back(valid.substr( current, (next == std::string::npos ? std::string::npos : next - current)));
            current = next + 1;
        } while (next != std::string::npos);
    }
}

ACLCertificateData::ACLCertificateData(ACLCertificateData const &old) : attribute (NULL), values (old.values), sslAttributeCall (old.sslAttributeCall)
{
    validAttributesStr = old.validAttributesStr;
    validAttributes.assign (old.validAttributes.begin(), old.validAttributes.end());
    attributeIsOptional = old.attributeIsOptional;
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
ACLCertificateData::match(X509 *cert)
{
    if (!cert)
        return 0;

    char const *value = sslAttributeCall(cert, attribute);
    debugs(28, 6, (attribute ? attribute : "value") << "=" << value);
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
    if (validAttributesStr)
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
    if (validAttributesStr) {
        char *newAttribute = strtokFile();

        if (!newAttribute) {
            if (attributeIsOptional)
                return;

            debugs(28, DBG_CRITICAL, "FATAL: required attribute argument missing");
            self_destruct();
        }

        // Handle the cases where we have optional -x type attributes
        if (attributeIsOptional && newAttribute[0] != '-')
            // The read token is not an attribute/option, so add it to values list
            values.insert(newAttribute);
        else {
            bool valid = false;
            for (std::list<std::string>::const_iterator it = validAttributes.begin(); it != validAttributes.end(); ++it) {
                if (*it == "*" || *it == newAttribute) {
                    valid = true;
                    break;
                }
            }

            if (!valid) {
                debugs(28, DBG_CRITICAL, "FATAL: Unknown option. Supported option(s) are: " << validAttributesStr);
                self_destruct();
            }

            /* an acl must use consistent attributes in all config lines */
            if (attribute) {
                if (strcasecmp(newAttribute, attribute) != 0) {
                    debugs(28, DBG_CRITICAL, "FATAL: An acl must use consistent attributes in all config lines (" << newAttribute << "!=" << attribute << ").");
                    self_destruct();
                }
            } else
                attribute = xstrdup(newAttribute);
        }
    }

    values.parse();
}

bool
ACLCertificateData::empty() const
{
    return values.empty();
}

ACLData<X509 *> *
ACLCertificateData::clone() const
{
    /* Splay trees don't clone yet. */
    return new ACLCertificateData(*this);
}
