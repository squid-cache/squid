/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_ACL_ARP_H
#define SQUID_SRC_ACL_ARP_H

#include "acl/Acl.h"

#include <set>

namespace Eui
{
class Eui48;
};

/// \ingroup ACLAPI
class ACLARP : public ACL
{
    MEMPROXY_CLASS(ACLARP);

public:
    ACLARP(char const *);
    ~ACLARP() override {}

    char const *typeString() const override;
    void parse() override;
    int match(ACLChecklist *checklist) override;
    SBufList dump() const override;
    bool empty () const override;

protected:
    char const *class_;
    typedef std::set<Eui::Eui48> AclArpData_t;
    AclArpData_t aclArpData;
};

#endif /* SQUID_SRC_ACL_ARP_H */

