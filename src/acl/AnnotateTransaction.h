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

namespace Acl
{

/// an "annotate_transaction" ACL
class AnnotateTransactionCheck: public Acl::AnnotationCheck
{
public:
    /* ACL API */
    int match(ACLChecklist *) override;
    bool requiresRequest() const override { return true; }
};

} // namespace Acl

#endif /* SQUID_ACLANNOTATETRANSACTION */

