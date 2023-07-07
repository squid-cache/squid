/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ACLATSTEP_H
#define SQUID_ACLATSTEP_H

#include "acl/Data.h"
#include "acl/ParameterizedNode.h"
#include "XactionStep.h"

namespace Acl
{

/// a "at_step" ACL
class AtStepCheck: public ParameterizedNode< ACLData<XactionStep> >
{
public:
    /* ACL API */
    int match(ACLChecklist *) override;
};

} // namespace Acl

#endif /* SQUID_ACLATSTEP_H */

