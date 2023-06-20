/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ACL_SOURCEASN_H
#define SQUID_ACL_SOURCEASN_H

#include "acl/Data.h"
#include "acl/ParameterizedNode.h"
#include "ip/forward.h"

namespace Acl
{

class SourceAsnCheck: public ParameterizedNode< ACLData<Ip::Address> >
{
public:
    /* ACL API */
    int match(ACLChecklist *) override;
};

} // namespace Acl

#endif /* SQUID_ACL_SOURCEASN_H */

