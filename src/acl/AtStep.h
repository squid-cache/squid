/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_ACL_ATSTEP_H
#define SQUID_SRC_ACL_ATSTEP_H

#include "acl/Strategy.h"
#include "XactionStep.h"

/// \ingroup ACLAPI
class ACLAtStepStrategy: public ACLStrategy<XactionStep>
{

public:
    int match (ACLData<MatchType> * &, ACLFilledChecklist *) override;
};

#endif /* SQUID_SRC_ACL_ATSTEP_H */

