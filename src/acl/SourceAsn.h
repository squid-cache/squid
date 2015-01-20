/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ACL_SOURCEASN_H
#define SQUID_ACL_SOURCEASN_H

#include "acl/Strategy.h"
#include "ip/Address.h"

class ACLChecklist;

class ACLSourceASNStrategy : public ACLStrategy<Ip::Address>
{

public:
    virtual int match (ACLData<MatchType> * &, ACLFilledChecklist *, ACLFlags &);
    static ACLSourceASNStrategy *Instance();
    /* Not implemented to prevent copies of the instance. */
    /* Not private to prevent brain dead g+++ warnings about
     * private constructors with no friends */
    ACLSourceASNStrategy(ACLSourceASNStrategy const &);

private:
    static ACLSourceASNStrategy Instance_;
    ACLSourceASNStrategy() {}

    ACLSourceASNStrategy&operator=(ACLSourceASNStrategy const &);
};

#endif /* SQUID_ACL_SOURCEASN_H */

