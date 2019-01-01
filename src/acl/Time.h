/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ACLTIME_H
#define SQUID_ACLTIME_H
#include "acl/Data.h"
#include "acl/Strategised.h"

class ACLTimeStrategy : public ACLStrategy<time_t>
{

public:
    virtual int match (ACLData<MatchType> * &, ACLFilledChecklist *) override;
};

#endif /* SQUID_ACLTIME_H */

