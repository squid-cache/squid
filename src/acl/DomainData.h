/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
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

class ACLDomainData : public ACLData<char const *>
{
    MEMPROXY_CLASS(ACLDomainData);

public:
    ACLDomainData() : domains(nullptr) {}
    virtual ~ACLDomainData();
    virtual bool match(char const *);
    virtual SBufList dump() const;
    void parse();
    bool empty() const;
    virtual ACLData<char const *> *clone() const;

    Splay<char *> *domains;
};

#endif /* SQUID_ACLDOMAINDATA_H */

