/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_ACL_SOURCEIP_H
#define SQUID_SRC_ACL_SOURCEIP_H

#include "acl/Ip.h"

class ACLSourceIP : public ACLIP
{
    MEMPROXY_CLASS(ACLSourceIP);

public:
    char const *typeString() const override;
    int match(ACLChecklist *checklist) override;
};

#endif /* SQUID_SRC_ACL_SOURCEIP_H */

