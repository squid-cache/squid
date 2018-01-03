/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ACLSERVERCERTIFICATE_H
#define SQUID_ACLSERVERCERTIFICATE_H

#include "acl/Acl.h"
#include "acl/Checklist.h"
#include "acl/Data.h"
#include "acl/Strategised.h"
#include "ssl/support.h"

/// \ingroup ACLAPI
class ACLServerCertificateStrategy : public ACLStrategy<X509 *>
{
public:
    virtual int match (ACLData<MatchType> * &, ACLFilledChecklist *) override;
};

#endif /* SQUID_ACLSERVERCERTIFICATE_H */

