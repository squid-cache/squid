/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
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
    ~ACLDomainData() override;
    bool match(char const *) override;
    SBufList dump() const override;
    void parse() override;
    bool empty() const override;

    Splay<char *> *domains;
};

#endif /* SQUID_ACLDOMAINDATA_H */

