/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ACLSOURCEDOMAIN_H
#define SQUID_ACLSOURCEDOMAIN_H

#include "acl/Checklist.h"
#include "acl/Data.h"
#include "acl/ParameterizedNode.h"
#include "dns/forward.h"

namespace Acl
{

/// a "srcdomain" or "srcdom_regex" ACL
class SourceDomainCheck: public ParameterizedNode< ACLData<const char *> >
{
public:
    /* AclNode API */
    int match(ACLChecklist *) override;
};

} // namespace Acl

#endif /* SQUID_ACLSOURCEDOMAIN_H */

