/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ACLMETHOD_H
#define SQUID_ACLMETHOD_H

#include "acl/Strategy.h"
#include "http/RequestMethod.h"

/// \ingroup ACLAPI
class ACLMethodStrategy : public ACLStrategy<HttpRequestMethod>
{

public:
    virtual int match (ACLData<MatchType> * &, ACLFilledChecklist *);
    virtual bool requiresRequest() const {return true;}
};

#endif /* SQUID_ACLMETHOD_H */

