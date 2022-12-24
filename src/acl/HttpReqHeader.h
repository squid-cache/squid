/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ACLHTTPREQHEADER_H
#define SQUID_ACLHTTPREQHEADER_H

#include "acl/Strategy.h"
#include "HttpHeader.h"

/// \ingroup ACLAPI
class ACLHTTPReqHeaderStrategy : public ACLStrategy<HttpHeader*>
{

public:
    virtual int match (ACLData<MatchType> * &, ACLFilledChecklist *);
    virtual bool requiresRequest() const { return true; }
};

#endif /* SQUID_ACLHTTPREQHEADER_H */

