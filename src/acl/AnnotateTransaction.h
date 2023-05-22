/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ACLANNOTATETRANSACTION
#define SQUID_ACLANNOTATETRANSACTION

#include "acl/Note.h"
#include "Notes.h"

/// \ingroup ACLAPI
class ACLAnnotateTransactionStrategy: public Acl::AnnotationStrategy
{
public:
    int match(ACLData<MatchType> * &, ACLFilledChecklist *) override;
    bool requiresRequest() const override { return true; }
};

#endif /* SQUID_ACLANNOTATETRANSACTION */

