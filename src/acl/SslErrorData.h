/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ACLSSL_ERRORDATA_H
#define SQUID_ACLSSL_ERRORDATA_H

#include "acl/Acl.h"
#include "acl/Data.h"
#include "security/forward.h"

class ACLSslErrorData : public ACLData<const Security::CertErrors *>
{
    MEMPROXY_CLASS(ACLSslErrorData);

public:
    ACLSslErrorData() = default;
    ACLSslErrorData(ACLSslErrorData const &);
    ACLSslErrorData &operator= (ACLSslErrorData const &);
    virtual ~ACLSslErrorData() {}
    bool match(const Security::CertErrors *);
    virtual SBufList dump() const;
    void parse();
    bool empty() const { return values.empty(); }
    virtual  ACLSslErrorData *clone() const;

    Security::Errors values;
};

#endif /* SQUID_ACLSSL_ERRORDATA_H */

