/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ACLASN_H
#define SQUID_ACLASN_H

#include "acl/Data.h"
#include "ip/Address.h"
#include "mem/PoolingAllocator.h"

#include <list>

/// \ingroup ACLAPI
void asnInit(void);

/// \ingroup ACLAPI
void asnFreeMemory(void);

/// \ingroup ACLAPI
class ACLASN : public ACLData<Ip::Address>
{
    MEMPROXY_CLASS(ACLASN);

public:
    using DataType = std::list<int, PoolingAllocator<int>>;

    virtual bool match(Ip::Address);
    virtual SBufList dump() const;
    virtual void parse();
    bool empty() const;
    virtual ACLData<Ip::Address> *clone() const;
    virtual void prepareForUse();

private:
    DataType data;
};

#endif /* SQUID_ACLASN_H */

