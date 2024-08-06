/*
 * Copyright (C) 1996-2024 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_ACL_SQUIDERROR_H
#define SQUID_SRC_ACL_SQUIDERROR_H

#include "acl/Strategy.h"
#include "error/forward.h"

class ACLSquidErrorStrategy : public ACLStrategy<err_type>
{

public:
    int match (ACLData<MatchType> * &, ACLFilledChecklist *) override;
};

#endif /* SQUID_SRC_ACL_SQUIDERROR_H */

