/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ACLNOTE_H
#define SQUID_ACLNOTE_H

#include "acl/Strategised.h"
#include "acl/Strategy.h"

class HttpRequest;

/// \ingroup ACLAPI
class ACLNoteStrategy : public ACLStrategy<HttpRequest *>
{

public:
    virtual int match (ACLData<MatchType> * &, ACLFilledChecklist *, ACLFlags &);
    virtual bool requiresRequest() const { return true; }

    static ACLNoteStrategy *Instance();
    /* Not implemented to prevent copies of the instance. */
    /* Not private to prevent brain dead g+++ warnings about
     * private constructors with no friends */
    ACLNoteStrategy(ACLNoteStrategy const &);

private:
    static ACLNoteStrategy Instance_;
    ACLNoteStrategy() { }

    ACLNoteStrategy& operator = (ACLNoteStrategy const &);
};

/// \ingroup ACLAPI
class ACLNote
{

private:
    static ACL::Prototype RegistryProtoype;
    static ACLStrategised<HttpRequest *> RegistryEntry_;
};

#endif /* SQUID_ACLNOTE_H */

