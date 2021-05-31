/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ACLCERTIFICATE_H
#define SQUID_ACLCERTIFICATE_H

#include "acl/Acl.h"
#include "acl/Checklist.h"
#include "acl/Data.h"
#include "acl/Strategised.h"
#include "ssl/support.h"

/// \ingroup ACLAPI
class ACLCertificateStrategy : public ACLStrategy<X509 *>
{

public:
    virtual int match (ACLData<MatchType> * &, ACLFilledChecklist *);
};

#endif /* SQUID_ACLCERTIFICATE_H */

