/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ACLASN_H
#define SQUID_ACLASN_H

#include "acl/Checklist.h"
#include "acl/Data.h"
#include "acl/Strategised.h"
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
    virtual ~ACLASN();

    virtual bool match(Ip::Address);
    virtual SBufList dump() const;
    virtual void parse();
    bool empty() const;
    virtual ACLData<Ip::Address> *clone() const;
    virtual void prepareForUse();

private:
    static ACL::Prototype SourceRegistryProtoype;
    static ACLStrategised<Ip::Address> SourceRegistryEntry_;
    static ACL::Prototype DestinationRegistryProtoype;
    static ACLStrategised<Ip::Address> DestinationRegistryEntry_;
    CbDataList<int> *data;
};

#endif /* SQUID_ACLASN_H */

