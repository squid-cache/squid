/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ACLSQUIDERROR_H
#define SQUID_ACLSQUIDERROR_H

#include "acl/Strategy.h"
#include "err_type.h"

class ACLSquidErrorStrategy : public ACLStrategy<err_type>
{

public:
    virtual int match (ACLData<MatchType> * &, ACLFilledChecklist *) override;
};

#endif /* SQUID_ACLSQUIDERROR_H */

