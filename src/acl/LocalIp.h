/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
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

public:
    MEMPROXY_CLASS(ACLLocalIP);
    static ACLLocalIP const &RegistryEntry();

    virtual char const *typeString() const;
    virtual int match(ACLChecklist *checklist);
    virtual ACL *clone()const;

private:
    static Prototype RegistryProtoype;
    static ACLLocalIP RegistryEntry_;
};

MEMPROXY_CLASS_INLINE(ACLLocalIP);

#endif /* SQUID_ACLLOCALIP_H */

