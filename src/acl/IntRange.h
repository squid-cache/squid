/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ACLINTRANGE_H
#define SQUID_ACLINTRANGE_H

#include "acl/Data.h"
#include "CbDataList.h"
#include "Range.h"

/// \ingroup ACLAPI
class ACLIntRange : public ACLData<int>
{

public:
    ACLIntRange() {};

    virtual ~ACLIntRange();
    virtual bool match(int);
    virtual SBufList dump() const;
    virtual void parse();
    virtual bool empty() const;
    virtual ACLData<int> *clone() const;

private:
    typedef Range<int> RangeType;
    CbDataListContainer <RangeType> ranges;
};

#endif /* SQUID_ACLINTRANGE_H */

