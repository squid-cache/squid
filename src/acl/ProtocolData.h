/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ACLPROTOCOLDATA_H
#define SQUID_ACLPROTOCOLDATA_H

#include "acl/Acl.h"
#include "acl/Data.h"
#include "anyp/ProtocolType.h"
#include "CbDataList.h"

class ACLProtocolData : public ACLData<AnyP::ProtocolType>
{

public:
    MEMPROXY_CLASS(ACLProtocolData);

    ACLProtocolData();
    ACLProtocolData(ACLProtocolData const &);
    ACLProtocolData &operator= (ACLProtocolData const &);
    virtual ~ACLProtocolData();
    bool match(AnyP::ProtocolType);
    virtual SBufList dump() const;
    void parse();
    bool empty() const;
    virtual ACLData<AnyP::ProtocolType> *clone() const;

    CbDataList<AnyP::ProtocolType> *values;
};

MEMPROXY_CLASS_INLINE(ACLProtocolData);

#endif /* SQUID_ACLPROTOCOLDATA_H */

