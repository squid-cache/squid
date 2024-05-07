/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_ACL_ADAPTATIONSERVICE_H
#define SQUID_SRC_ACL_ADAPTATIONSERVICE_H

#include "acl/Data.h"
#include "acl/ParameterizedNode.h"

namespace Acl
{

/// an "adaptation_service" ACL
class AdaptationServiceCheck: public ParameterizedNode< ACLData<const char *> >
{
public:
    /* Acl::Node API */
    int match(ACLChecklist *) override;
};

} // namespace Acl

#endif /* SQUID_SRC_ACL_ADAPTATIONSERVICE_H */

