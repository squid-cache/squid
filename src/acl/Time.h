/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_ACL_TIME_H
#define SQUID_SRC_ACL_TIME_H

#include "acl/ParameterizedNode.h"
#include "acl/TimeData.h"
#include "mem/AllocatorProxy.h"

namespace Acl
{

class Time: public ParameterizedNode<ACLTimeData>
{
    MEMPROXY_CLASS(Acl::Time);

public:
    /* ACL API */
    char const *typeString() const override { return "time"; }
    int match(ACLChecklist *) override;
};

} // namespace Acl

#endif /* SQUID_SRC_ACL_TIME_H */

