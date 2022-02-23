/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ADAPTATIONSERVICEDATA_H
#define SQUID_ADAPTATIONSERVICEDATA_H

#include "acl/Acl.h"
#include "acl/Data.h"
#include "acl/StringData.h"

/// \ingroup ACLAPI
class ACLAdaptationServiceData : public ACLStringData
{
public:
    ACLAdaptationServiceData() : ACLStringData() {}
    virtual void parse();
};

#endif /* SQUID_ADAPTATIONSERVICEDATA_H */

