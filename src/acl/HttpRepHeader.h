/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_ACL_HTTPREPHEADER_H
#define SQUID_SRC_ACL_HTTPREPHEADER_H

#include "acl/Strategised.h"
#include "acl/Strategy.h"
#include "HttpHeader.h"

/// \ingroup ACLAPI
class ACLHTTPRepHeaderStrategy : public ACLStrategy<HttpHeader*>
{

public:
    int match (ACLData<MatchType> * &, ACLFilledChecklist *) override;
    bool requiresReply() const override { return true; }
};

#endif /* SQUID_SRC_ACL_HTTPREPHEADER_H */

