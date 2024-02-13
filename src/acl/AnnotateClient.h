/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_ACL_ANNOTATECLIENT_H
#define SQUID_SRC_ACL_ANNOTATECLIENT_H

#include "acl/Note.h"
#include "Notes.h"

/// \ingroup ACLAPI
class ACLAnnotateClientStrategy : public Acl::AnnotationStrategy
{
public:
    bool requiresRequest() const override { return true; }
    int match(ACLData<MatchType> * &, ACLFilledChecklist *) override;
};

#endif /* SQUID_SRC_ACL_ANNOTATECLIENT_H */

