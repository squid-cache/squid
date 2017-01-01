/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ACLDOMAINDATA_H
#define SQUID_ACLDOMAINDATA_H

#include "acl/Acl.h"
#include "acl/Data.h"
#include "splay.h"

/// \ingroup ACLAPI
class ACLDomainData : public ACLData<char const *>
{

public:
    MEMPROXY_CLASS(ACLDomainData);

    virtual ~ACLDomainData();
    virtual bool match(char const *);
    virtual SBufList dump() const;
    void parse();
    bool empty() const;
    virtual ACLData<char const *> *clone() const;

    Splay<char *> *domains;
};

MEMPROXY_CLASS_INLINE(ACLDomainData);

#endif /* SQUID_ACLDOMAINDATA_H */

