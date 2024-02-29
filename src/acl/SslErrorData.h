/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_ACL_SSLERRORDATA_H
#define SQUID_SRC_ACL_SSLERRORDATA_H

#include "acl/Acl.h"
#include "acl/Data.h"
#include "security/forward.h"

class ACLSslErrorData : public ACLData<const Security::CertErrors *>
{
    MEMPROXY_CLASS(ACLSslErrorData);

public:
    ACLSslErrorData() = default;
    ~ACLSslErrorData() override {}
    bool match(const Security::CertErrors *) override;
    SBufList dump() const override;
    void parse() override;
    bool empty() const override { return values.empty(); }

    Security::Errors values;
};

#endif /* SQUID_SRC_ACL_SSLERRORDATA_H */

