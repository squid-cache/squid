/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ACLBROWSER_H
#define SQUID_ACLBROWSER_H

#include "acl/Acl.h"
#include "acl/Data.h"
#include "acl/RequestHeaderStrategy.h"
#include "acl/Strategised.h"

/// \ingroup ACLAPI
class ACLBrowser
{

private:
    static ACL::Prototype RegistryProtoype;
    static ACLStrategised<char const *> RegistryEntry_;
};

#endif /* SQUID_ACLBROWSER_H */

