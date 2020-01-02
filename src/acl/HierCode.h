/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ACLHIERCODE_H
#define SQUID_ACLHIERCODE_H

#include "acl/Strategy.h"
#include "hier_code.h"

/// \ingroup ACLAPI
class ACLHierCodeStrategy : public ACLStrategy<hier_code>
{

public:
    virtual int match (ACLData<MatchType> * &, ACLFilledChecklist *);
    virtual bool requiresRequest() const {return true;}
};

#endif /* SQUID_ACLHIERCODE_H */

