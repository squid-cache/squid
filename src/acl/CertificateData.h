/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ACLCERTIFICATEDATA_H
#define SQUID_ACLCERTIFICATEDATA_H

#include "acl/Acl.h"
#include "acl/Data.h"
#include "acl/StringData.h"
#include "ssl/support.h"
#include <string>
#include <list>

/// \ingroup ACLAPI
class ACLCertificateData : public ACLData<X509 *>
{
    MEMPROXY_CLASS(ACLCertificateData);

public:
    ACLCertificateData(Ssl::GETX509ATTRIBUTE *, const char *attributes, bool optionalAttr = false);
    ACLCertificateData(ACLCertificateData const &);
    ACLCertificateData &operator= (ACLCertificateData const &);
    virtual ~ACLCertificateData();
    bool match(X509 *);
    virtual SBufList dump() const;
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

#endif /* SQUID_ACLCERTIFICATEDATA_H */

