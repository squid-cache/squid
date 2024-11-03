/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_ACL_ASN_H
#define SQUID_SRC_ACL_ASN_H

#include "acl/Data.h"
#include "base/CbDataList.h"
#include "ip/Address.h"

int asnMatchIp(CbDataList<int> *, Ip::Address &);

/// \ingroup ACLAPI
void asnInit(void);

/// \ingroup ACLAPI
void asnFreeMemory(void);

/// \ingroup ACLAPI
class ACLASN : public ACLData<Ip::Address>
{
    MEMPROXY_CLASS(ACLASN);

public:
    ACLASN() : data(nullptr) {}
    ~ACLASN() override;

    bool match(Ip::Address) override;
    SBufList dump() const override;
    void parse() override;
    bool empty() const override;
    void prepareForUse() override;

private:
    CbDataList<int> *data;
};

#endif /* SQUID_SRC_ACL_ASN_H */

