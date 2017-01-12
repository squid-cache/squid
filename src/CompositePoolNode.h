/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 77    Delay Pools */

#ifndef COMPOSITEPOOLNODE_H
#define COMPOSITEPOOLNODE_H

#if USE_DELAY_POOLS
#include "auth/UserRequest.h"
#include "CommRead.h"
#include "DelayIdComposite.h"
#include "DelayPools.h"
#include "ip/Address.h"
#include "SquidString.h"

class StoreEntry;

/// \ingroup DelayPoolsAPI
class CompositePoolNode : public RefCountable, public Updateable
{

public:
    typedef RefCount<CompositePoolNode> Pointer;
    void *operator new(size_t);
    void operator delete (void *);
    virtual ~CompositePoolNode() {}

    virtual void stats(StoreEntry * sentry) =0;
    virtual void dump(StoreEntry *entry) const =0;
    virtual void update(int incr) =0;
    virtual void parse() = 0;

    class CompositeSelectionDetails;
    virtual DelayIdComposite::Pointer id(CompositeSelectionDetails &) = 0;
    void delayRead(DeferredRead const &);

    /// \ingroup DelayPoolsAPI
    class CompositeSelectionDetails
    {

    public:
        CompositeSelectionDetails() {}

        Ip::Address src_addr;
#if USE_AUTH
        Auth::UserRequest::Pointer user;
#endif
        String tag;
    };

protected:
    void kickReads();
    DeferredReadManager deferredReads;
};

#endif /* USE_DELAY_POOLS */
#endif /* COMPOSITEPOOLNODE_H */

