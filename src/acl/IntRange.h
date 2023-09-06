/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ACLINTRANGE_H
#define SQUID_ACLINTRANGE_H

#include "acl/Data.h"
#include "base/Range.h"

#include <list>

class ACLIntRange : public ACLData<int>
{

public:
    ACLIntRange() {}

    ~ACLIntRange() override;
    bool match(int) override;
    SBufList dump() const override;
    void parse() override;
    bool empty() const override;

private:
    typedef Range<int> RangeType;
    std::list<RangeType> ranges;
};

#endif /* SQUID_ACLINTRANGE_H */

