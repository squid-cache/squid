/*
 * Copyright (C) 1996-2026 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_ACL_SNMP_H
#define SQUID_SRC_ACL_SNMP_H

#if SQUID_SNMP

#include "acl/Data.h"
#include "acl/ParameterizedNode.h"

namespace Acl
{
namespace Snmp
{

/// an "snmp_community" ACL
class CommunityCheck: public ParameterizedNode< ACLData<const char *> >
{
public:
    /* Acl::Node API */
    int match(ACLChecklist *) override;
};

} // namespace Snmp
} // namespace Acl

#endif // SQUID_SNMP
#endif /* _SQUID__SRC_ACL_SNMP_H */
