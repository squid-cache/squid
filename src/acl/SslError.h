/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ACLSSL_ERROR_H
#define SQUID_ACLSSL_ERROR_H

#include "acl/Strategy.h"
#include "security/forward.h"

class ACLSslErrorStrategy : public ACLStrategy<const Security::CertErrors *>
{

public:
    virtual int match (ACLData<MatchType> * &, ACLFilledChecklist *) override;
};

#endif /* SQUID_ACLSSL_ERROR_H */

