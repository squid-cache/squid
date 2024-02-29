/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 77    Delay Pools */

#ifndef SQUID_SRC_COMPOSITEPOOLNODE_H
#define SQUID_SRC_COMPOSITEPOOLNODE_H

#if USE_DELAY_POOLS
#include "auth/UserRequest.h"
#include "base/DelayedAsyncCalls.h"
#include "DelayIdComposite.h"
#include "DelayPools.h"
#include "ip/Address.h"
#include "sbuf/SBuf.h"

class StoreEntry;

/// \ingroup DelayPoolsAPI
class CompositePoolNode : public RefCountable, public Updateable
{
    MEMPROXY_CLASS(CompositePoolNode);

public:
    typedef RefCount<CompositePoolNode> Pointer;
    ~CompositePoolNode() override {}

    virtual void stats(StoreEntry * sentry) =0;
    virtual void dump(StoreEntry *entry) const =0;
    void update(int incr) override =0;
    virtual void parse() = 0;

    class CompositeSelectionDetails;
    virtual DelayIdComposite::Pointer id(CompositeSelectionDetails &) = 0;
    void delayRead(const AsyncCallPointer &);

    /// \ingroup DelayPoolsAPI
    class CompositeSelectionDetails
    {

    public:
        CompositeSelectionDetails(const Ip::Address& aSrcAddr, const SBuf &aTag) :
            src_addr(aSrcAddr), tag(aTag)
        {}

        Ip::Address src_addr;
#if USE_AUTH
        Auth::UserRequest::Pointer user;
#endif
        const SBuf tag;
    };

protected:
    void kickReads();
    DelayedAsyncCalls deferredReads;
};

#endif /* USE_DELAY_POOLS */
#endif /* SQUID_SRC_COMPOSITEPOOLNODE_H */

