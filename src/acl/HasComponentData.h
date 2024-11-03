/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_ACL_HASCOMPONENTDATA_H
#define SQUID_SRC_ACL_HASCOMPONENTDATA_H

#include "acl/Checklist.h"
#include "acl/Data.h"

/// \ingroup ACLAPI
class ACLHasComponentData : public ACLData<ACLChecklist *>
{
    MEMPROXY_CLASS(ACLHasComponentData);

public:
    ACLHasComponentData();

    /* ACLData<M> API */
    bool match(ACLChecklist *) override;
    SBufList dump() const override;
    void parse() override;
    bool empty() const override { return false; }

private:
    enum ComponentKind { coRequest = 0, coResponse, coAle, coEnd };
    void parseComponent(const char *token);

    static const SBuf RequestStr;
    static const SBuf ResponseStr;
    static const SBuf AleStr;

    typedef bool (ACLChecklist::*ComponentCheck)() const;
    /// component check callbacks, ordered by component kind ID
    std::vector<ComponentCheck> componentMethods;
};

#endif /* SQUID_SRC_ACL_HASCOMPONENTDATA_H */

