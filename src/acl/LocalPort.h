/*
 * Copyright (C) 1996-2024 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_ACL_LOCALPORT_H
#define SQUID_SRC_ACL_LOCALPORT_H

#include "acl/Strategy.h"

/// \ingroup ACLAPI
class ACLLocalPortStrategy : public ACLStrategy<int>
{

public:
    int match (ACLData<MatchType> * &, ACLFilledChecklist *) override;
};

#endif /* SQUID_SRC_ACL_LOCALPORT_H */

