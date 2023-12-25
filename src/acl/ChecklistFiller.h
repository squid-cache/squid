/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ACL_CHECKLIST_FILLER_H
#define SQUID_ACL_CHECKLIST_FILLER_H

#include "acl/forward.h"

namespace Acl
{

/// an interface for those capable of configuring an ACLFilledChecklist object
class ChecklistFiller
{
public:
    virtual ~ChecklistFiller() = default;

    /// configure the given checklist (to reflect the current transaction state)
    virtual void fillChecklist(ACLFilledChecklist &) const = 0;
};

} // namespace Acl

#endif /* SQUID_ACL_CHECKLIST_FILLER_H */

