/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ACLSOURCEIP_H
#define SQUID_ACLSOURCEIP_H

#include "acl/Ip.h"

class ACLSourceIP : public ACLIP
{
    MEMPROXY_CLASS(ACLSourceIP);

public:
    virtual char const *typeString() const;
    virtual int match(ACLChecklist *checklist);
    virtual ACL *clone()const;
};

#endif /* SQUID_ACLSOURCEIP_H */

