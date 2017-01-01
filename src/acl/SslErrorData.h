/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ACLSSL_ERRORDATA_H
#define SQUID_ACLSSL_ERRORDATA_H
#include "acl/Acl.h"
#include "acl/Data.h"
#include "CbDataList.h"
#include "ssl/ErrorDetail.h"
#include "ssl/support.h"
#include <vector>

class ACLSslErrorData : public ACLData<const Ssl::CertErrors *>
{

public:
    MEMPROXY_CLASS(ACLSslErrorData);

    ACLSslErrorData();
    ACLSslErrorData(ACLSslErrorData const &);
    ACLSslErrorData &operator= (ACLSslErrorData const &);
    virtual ~ACLSslErrorData();
    bool match(const Ssl::CertErrors *);
    virtual SBufList dump() const;
    void parse();
    bool empty() const;
    virtual  ACLSslErrorData *clone() const;

    Ssl::Errors *values;
};

MEMPROXY_CLASS_INLINE(ACLSslErrorData);

#endif /* SQUID_ACLSSL_ERRORDATA_H */

