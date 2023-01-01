/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ACL_TRANSACTION_INITIATOR_H
#define SQUID_ACL_TRANSACTION_INITIATOR_H

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

    virtual ACL *clone()const;
    virtual char const *typeString() const;
    virtual void parse();
    virtual int match(ACLChecklist *checklist);
    virtual bool requiresRequest() const { return true; }
    virtual SBufList dump() const;
    virtual bool empty () const;

protected:
    char const *class_;
    XactionInitiator::Initiators initiators_;
    SBufList cfgWords; /// initiator names in the configured order
};

} // namespace Acl

#endif /* SQUID_ACL_TRANSACTION_INITIATOR_H */

