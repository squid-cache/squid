/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ACLMETHOD_H
#define SQUID_ACLMETHOD_H

#include "acl/Data.h"
#include "acl/ParameterizedNode.h"
#include "http/RequestMethod.h"

namespace Acl
{

/// a "method" ACL
class MethodCheck: public ParameterizedNode< ACLData<HttpRequestMethod> >
{
public:
    /* ACL API */
    int match(ACLChecklist *) override;
    bool requiresRequest() const override {return true;}
};

} // namespace Acl

#endif /* SQUID_ACLMETHOD_H */

