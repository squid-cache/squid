/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_ACL_ADAPTATIONSERVICEDATA_H
#define SQUID_SRC_ACL_ADAPTATIONSERVICEDATA_H

#include "acl/Acl.h"
#include "acl/Data.h"
#include "acl/StringData.h"

/// \ingroup ACLAPI
class ACLAdaptationServiceData : public ACLStringData
{
public:
    ACLAdaptationServiceData() : ACLStringData() {}
    void parse() override;
};

#endif /* SQUID_SRC_ACL_ADAPTATIONSERVICEDATA_H */

