/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_ACL_STRATEGY_H
#define SQUID_SRC_ACL_STRATEGY_H

#include "acl/Acl.h"
#include "acl/Data.h"
#include "acl/Options.h"

class ACLFilledChecklist;

template<class M>

/// A matching algorithm.
class ACLStrategy
{

public:
    typedef M MatchType;

    /* Replicate ACL API parts relevant to the matching algorithm. */
    virtual const Acl::Options &options() { return Acl::NoOptions(); }
    virtual int match (ACLData<M> * &, ACLFilledChecklist *) = 0;
    virtual bool requiresRequest() const {return false;}

    virtual bool requiresReply() const {return false;}

    virtual bool valid() const {return true;}

    virtual ~ACLStrategy() {}
};

#endif /* SQUID_SRC_ACL_STRATEGY_H */

