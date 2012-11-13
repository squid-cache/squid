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
 *
 * Copyright (c) 2003, Robert Collins <robertc@squid-cache.org>
 */

#ifndef SQUID_ACLCERTIFICATEDATA_H
#define SQUID_ACLCERTIFICATEDATA_H

#include "splay.h"
#include "acl/Acl.h"
#include "acl/Data.h"
#include "ssl/support.h"
#include "acl/StringData.h"
#include <string>
#include <list>

/// \ingroup ACLAPI
class ACLCertificateData : public ACLData<X509 *>
{

public:
    MEMPROXY_CLASS(ACLCertificateData);

    ACLCertificateData(Ssl::GETX509ATTRIBUTE *, const char *attributes, bool optionalAttr = false);
    ACLCertificateData(ACLCertificateData const &);
    ACLCertificateData &operator= (ACLCertificateData const &);
    virtual ~ACLCertificateData();
    bool match(X509 *);
    wordlist *dump();
    void parse();
    bool empty() const;
    virtual ACLData<X509 *> *clone() const;

    /// A '|'-delimited list of valid ACL attributes.
    /// A "*" item means that any attribute is acceptable.
    /// Assumed to be a const-string and is never duped/freed.
    /// Nil unless ACL form is: acl Name type attribute value1 ...
    const char *validAttributesStr;
    /// Parsed list of valid attribute names
    std::list<std::string> validAttributes;
    /// True if the attribute is optional (-xxx options)
    bool attributeIsOptional;
    char *attribute;
    ACLStringData values;

private:
    /// The callback used to retrieve the data from X509 cert
    Ssl::GETX509ATTRIBUTE *sslAttributeCall;
};

MEMPROXY_CLASS_INLINE(ACLCertificateData);

#endif /* SQUID_ACLCERTIFICATEDATA_H */
