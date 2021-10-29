/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ACLADAPTATIONREPHEADER_H
#define SQUID_ACLADAPTATIONREPHEADER_H

#include "acl/Strategy.h"

class HttpHeader;

/// adaptation_rep_header
class ACLAdaptationRepHeaderStrategy: public ACLStrategy<HttpHeader*>
{
public:
    ACLAdaptationRepHeaderStrategy();
    virtual int match (ACLData<MatchType> * &, ACLFilledChecklist *);
    virtual bool requiresRequest() const { return true; }
};

#endif /* SQUID_ACLADAPTATIONREPHEADER_H */

