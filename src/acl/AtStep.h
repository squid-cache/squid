/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ACLATSTEP_H
#define SQUID_ACLATSTEP_H

#include "acl/Strategy.h"

/// \ingroup ACLAPI
class ACLAtStepStrategy : public ACLStrategy<int>
{

public:
    virtual int match (ACLData<MatchType> * &, ACLFilledChecklist *) override;
};


#endif /* SQUID_ACLATSTEP_H */

