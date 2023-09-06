/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ACLLOCALIP_H
#define SQUID_ACLLOCALIP_H

#include "acl/Ip.h"

/// \ingroup ACLAPI
class ACLLocalIP : public ACLIP
{
    MEMPROXY_CLASS(ACLLocalIP);

public:
    char const *typeString() const override;
    int match(ACLChecklist *checklist) override;
};

#endif /* SQUID_ACLLOCALIP_H */

