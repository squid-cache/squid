/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ACLSERVERNAME_H
#define SQUID_ACLSERVERNAME_H

#include "acl/Acl.h"
#include "acl/DomainData.h"
#include "acl/Strategy.h"

class ACLServerNameData : public ACLDomainData {
    MEMPROXY_CLASS(ACLServerNameData);
public:
    ACLServerNameData() : ACLDomainData() {}
    virtual bool match(const char *);
    virtual ACLData<char const *> *clone() const;
};

class ACLServerNameStrategy : public ACLStrategy<char const *>
{

public:
    /* ACLStrategy API */
    virtual int match (ACLData<MatchType> * &, ACLFilledChecklist *);
    virtual bool requiresRequest() const {return true;}

};

#endif /* SQUID_ACLSERVERNAME_H */

