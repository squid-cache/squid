/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_ACL_TRANSACTIONINITIATOR_H
#define SQUID_SRC_ACL_TRANSACTIONINITIATOR_H

#include "acl/Acl.h"
#include "acl/Checklist.h"
#include "XactionInitiator.h"

namespace Acl
{

/// transaction_initiator ACL
class TransactionInitiator : public ACL
{
    MEMPROXY_CLASS(TransactionInitiator);

public:
    TransactionInitiator(char const *);

    char const *typeString() const override;
    void parse() override;
    int match(ACLChecklist *checklist) override;
    bool requiresRequest() const override { return true; }
    SBufList dump() const override;
    bool empty () const override;

protected:
    char const *class_;
    XactionInitiator::Initiators initiators_;
    SBufList cfgWords; /// initiator names in the configured order
};

} // namespace Acl

#endif /* SQUID_SRC_ACL_TRANSACTIONINITIATOR_H */

