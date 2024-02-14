/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_ACL_TIME_H
#define SQUID_SRC_ACL_TIME_H
#include "acl/Data.h"
#include "acl/Strategised.h"

class ACLTimeStrategy : public ACLStrategy<time_t>
{

public:
    int match (ACLData<MatchType> * &, ACLFilledChecklist *) override;
};

#endif /* SQUID_SRC_ACL_TIME_H */

