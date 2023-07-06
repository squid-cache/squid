/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ACLPEERNAME_H
#define SQUID_ACLPEERNAME_H

#include "acl/Data.h"
#include "acl/ParameterizedNode.h"

namespace Acl
{

/// a "peername" or "peername_regex" ACL
class PeerNameCheck: public ParameterizedNode< ACLData<const char *> >
{
public:
    /* ACL API */
    int match(ACLChecklist *) override;
};

} // namespace Acl

#endif /* SQUID_ACLPEERNAME_H */

