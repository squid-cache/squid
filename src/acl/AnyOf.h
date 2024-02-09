/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_ACL_ANYOF_H
#define SQUID_SRC_ACL_ANYOF_H

#include "acl/BoolOps.h"

namespace Acl
{

/// Configurable any-of ACL. Each ACL line is a disjuction of ACLs.
class AnyOf: public Acl::OrNode
{
    MEMPROXY_CLASS(AnyOf);

public:
    /* Acl::Node API */
    char const *typeString() const override;
    void parse() override;
};

} // namespace Acl

#endif /* SQUID_SRC_ACL_ANYOF_H */

