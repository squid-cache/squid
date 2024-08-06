/*
 * Copyright (C) 1996-2024 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_ACL_HTTPREQHEADER_H
#define SQUID_SRC_ACL_HTTPREQHEADER_H

#include "acl/Strategy.h"
#include "HttpHeader.h"

/// \ingroup ACLAPI
class ACLHTTPReqHeaderStrategy : public ACLStrategy<HttpHeader*>
{

public:
    int match (ACLData<MatchType> * &, ACLFilledChecklist *) override;
    bool requiresRequest() const override { return true; }
};

#endif /* SQUID_SRC_ACL_HTTPREQHEADER_H */

