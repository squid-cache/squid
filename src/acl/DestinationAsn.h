/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ACLDESTINATIONASN_H
#define SQUID_ACLDESTINATIONASN_H

#include "acl/Asn.h"
#include "acl/Strategy.h"
#include "ip/Address.h"

/// \ingroup ACLAPI
class ACLDestinationASNStrategy : public ACLStrategy<Ip::Address>
{

public:
    virtual int match (ACLData<MatchType> * &, ACLFilledChecklist *, ACLFlags &);
    virtual bool requiresRequest() const {return true;}

    static ACLDestinationASNStrategy *Instance();

    /**
     * Not implemented to prevent copies of the instance.
     \par
     * Not private to prevent brain dead g++ warnings about
     * private constructors with no friends
     */
    ACLDestinationASNStrategy(ACLDestinationASNStrategy const &);

private:
    static ACLDestinationASNStrategy Instance_;
    ACLDestinationASNStrategy() {}

    ACLDestinationASNStrategy&operator=(ACLDestinationASNStrategy const &);
};

#endif /* SQUID_ACLDESTINATIONASN_H */

