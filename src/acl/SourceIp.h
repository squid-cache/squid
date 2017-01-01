/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
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

public:
    MEMPROXY_CLASS(ACLSourceIP);

    virtual char const *typeString() const;
    virtual int match(ACLChecklist *checklist);
    virtual ACL *clone()const;

private:
    static Prototype RegistryProtoype;
    static ACLSourceIP RegistryEntry_;
};

MEMPROXY_CLASS_INLINE(ACLSourceIP);

#endif /* SQUID_ACLSOURCEIP_H */

