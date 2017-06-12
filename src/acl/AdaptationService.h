/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ACLADAPTATIONSERVICE_H
#define SQUID_ACLADAPTATIONSERVICE_H

#include "acl/Strategy.h"

/// \ingroup ACLAPI
class ACLAdaptationServiceStrategy : public ACLStrategy<const char *>
{

public:
    virtual int match (ACLData<MatchType> * &, ACLFilledChecklist *) override;
};

#endif /* SQUID_ACLADAPTATIONSERVICE_H */

