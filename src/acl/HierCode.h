/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ACLHIERCODE_H
#define SQUID_ACLHIERCODE_H

#include "acl/Data.h"
#include "acl/ParameterizedNode.h"
#include "hier_code.h"

namespace Acl
{

/// a "hier_code" ACL
class HierCodeCheck: public ParameterizedNode< ACLData<hier_code> >
{
public:
    /* ACL API */
    int match(ACLChecklist *) override;
    bool requiresRequest() const override {return true;}
};

} // namespace Acl

#endif /* SQUID_ACLHIERCODE_H */

