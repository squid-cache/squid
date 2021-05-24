/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ACLANNOTATECLIENT
#define SQUID_ACLANNOTATECLIENT

#include "acl/Note.h"
#include "Notes.h"

/// \ingroup ACLAPI
class ACLAnnotateClientStrategy : public Acl::AnnotationStrategy
{
public:
    virtual bool requiresRequest() const { return true; }
    virtual int match(ACLData<MatchType> * &, ACLFilledChecklist *);
};

#endif /* SQUID_ACLANNOTATECLIENT */

