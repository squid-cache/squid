/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ACLSTRATEGY_H
#define SQUID_ACLSTRATEGY_H

#include "acl/Acl.h"
#include "acl/Data.h"

class ACLFilledChecklist;

template<class M>

class ACLStrategy
{

public:
    typedef M MatchType;
    virtual int match (ACLData<M> * &, ACLFilledChecklist *, ACLFlags &) = 0;
    virtual bool requiresRequest() const {return false;}

    virtual bool requiresReply() const {return false;}

    virtual bool valid() const {return true;}

    virtual ~ACLStrategy() {}
};

#endif /* SQUID_ACLSTRATEGY_H */

