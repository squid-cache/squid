/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ACLURLPORT_H
#define SQUID_ACLURLPORT_H

#include "acl/Strategy.h"

class ACLUrlPortStrategy : public ACLStrategy<int>
{

public:
    int match (ACLData<MatchType> * &, ACLFilledChecklist *) override;
    bool requiresRequest() const override {return true;}
};

#endif /* SQUID_ACLURLPORT_H */

