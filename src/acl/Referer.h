/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ACLREFERER_H
#define SQUID_ACLREFERER_H
#include "acl/Acl.h"
#include "acl/Data.h"
#include "acl/RequestHeaderStrategy.h"
#include "acl/Strategised.h"

class ACLReferer
{

private:
    static ACL::Prototype RegistryProtoype;
    static ACLStrategised<char const *> RegistryEntry_;
};

#endif /* SQUID_ACLREFERER_H */

