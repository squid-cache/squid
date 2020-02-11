/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 28    Access Control */

#include "squid.h"
#include "acl/CertificateData.h"
#include "acl/Checklist.h"
#include "cache_cf.h"
#include "ConfigParser.h"
#include "Debug.h"
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
        attribute = xstrdup(old.attribute);
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

SBufList
ACLCertificateData::dump() const
{
    SBufList sl;
    if (validAttributesStr)
        sl.push_back(SBuf(attribute));

#if __cplusplus >= 201103L
    sl.splice(sl.end(),values.dump());
#else
    // temp is needed until c++11 move constructor
    SBufList tmp = values.dump();
    sl.splice(sl.end(),tmp);
#endif
    return sl;
}

void
ACLCertificateData::parse()
{
    if (validAttributesStr) {
        char *newAttribute = ConfigParser::strtokFile();

        if (!newAttribute) {
            if (!attributeIsOptional) {
                debugs(28, DBG_CRITICAL, "FATAL: required attribute argument missing");
                self_destruct();
            }
            return;
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
                return;
            }

            /* an acl must use consistent attributes in all config lines */
            if (attribute) {
                if (strcasecmp(newAttribute, attribute) != 0) {
                    debugs(28, DBG_CRITICAL, "FATAL: An acl must use consistent attributes in all config lines (" << newAttribute << "!=" << attribute << ").");
                    self_destruct();
                    return;
                }
            } else {
                if (strcasecmp(newAttribute, "DN") != 0) {
                    int nid = OBJ_txt2nid(newAttribute);
                    if (nid == 0) {
                        const size_t span = strspn(newAttribute, "0123456789.");
                        if(newAttribute[span] == '\0') { // looks like a numerical OID
                            // create a new object based on this attribute

                            // NOTE: Not a [bad] leak: If the same attribute
                            // has been added before, the OBJ_txt2nid call
                            // would return a valid nid value.
                            // TODO: call OBJ_cleanup() on reconfigure?
                            nid = OBJ_create(newAttribute, newAttribute,  newAttribute);
                            debugs(28, 7, "New SSL certificate attribute created with name: " << newAttribute << " and nid: " << nid);
                        }
                    }
                    if (nid == 0) {
                        debugs(28, DBG_CRITICAL, "FATAL: Not valid SSL certificate attribute name or numerical OID: " << newAttribute);
                        self_destruct();
                        return;
                    }
                }
                attribute = xstrdup(newAttribute);
            }
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

