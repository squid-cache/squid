/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 77    Delay Pools */

#include "squid.h"

/* MS Visual Studio Projects are monolithic, so we need the following
 * #if to exclude the delay pools code from compile process when not needed.
 */
#if USE_DELAY_POOLS
#include "acl/FilledChecklist.h"
#include "base/DelayedAsyncCalls.h"
#include "client_side_request.h"
#include "DelayId.h"
#include "DelayPool.h"
#include "DelayPools.h"
#include "http/Stream.h"
#include "HttpRequest.h"
#include "sbuf/StringConvert.h"
#include "SquidConfig.h"

DelayId::DelayId () : pool_ (0), compositeId(nullptr), markedAsNoDelay(false)
{}

DelayId::DelayId(const unsigned short aPool, const DelayIdComposite::Pointer &aCompositeId):
    pool_(aPool), compositeId(aCompositeId), markedAsNoDelay(false)
{
    assert(pool_);
    assert(compositeId);
    debugs(77, 3, "DelayId::DelayId: Pool " << aPool << "u");
}

DelayId::~DelayId ()
{}

unsigned short
DelayId::pool() const
{
    return pool_;
}

bool
DelayId::operator == (DelayId const &rhs) const
{
    /* Doesn't compare composites properly....
     * only use to test against default ID's
     */
    return pool_ == rhs.pool_ && compositeId == rhs.compositeId;
}

DelayId::operator bool() const
{
    return compositeId && !markedAsNoDelay;
}

/* create a delay Id for a given request */
DelayId
DelayId::DelayClient(ClientHttpRequest * http, HttpReply *reply)
{
    HttpRequest *r;
    unsigned short pool;
    assert(http);
    r = http->request;

    if (r->client_addr.isNoAddr()) {
        debugs(77, 2, "delayClient: WARNING: Called with 'NO_ADDR' address, ignoring");
        return DelayId();
    }

    for (pool = 0; pool < DelayPools::pools(); ++pool) {

        /* pools require explicit 'allow' to assign a client into them */
        if (!DelayPools::delay_data[pool].access) {
            debugs(77, DBG_IMPORTANT, "delay_pool " << pool <<
                   " has no delay_access configured. This means that no clients will ever use it.");
            continue;
        }

        ACLFilledChecklist ch(DelayPools::delay_data[pool].access, r);
        clientAclChecklistFill(ch, http);
        ch.updateReply(reply);
        // overwrite ACLFilledChecklist acl_uses_indirect_client-based decision
#if FOLLOW_X_FORWARDED_FOR
        if (Config.onoff.delay_pool_uses_indirect_client)
            ch.src_addr = r->indirect_client_addr;
        else
#endif /* FOLLOW_X_FORWARDED_FOR */
            ch.src_addr = r->client_addr;

        if (DelayPools::delay_data[pool].theComposite().getRaw() && ch.fastCheck().allowed()) {
            CompositePoolNode::CompositeSelectionDetails details(ch.src_addr, StringToSBuf(r->tag));
#if USE_AUTH
            details.user = r->auth_user_request;
#endif
            return DelayId(pool + 1, DelayPools::delay_data[pool].theComposite()->id(details));
        }
    }

    return DelayId();
}

void
DelayId::setNoDelay(bool const newValue)
{
    markedAsNoDelay = newValue;
}

/*
 * this returns the number of bytes the client is permitted. it does not take
 * into account bytes already buffered - that is up to the caller.
 */
int
DelayId::bytesWanted(int minimum, int maximum) const
{
    const auto maxBytes = max(minimum, maximum);

    if (! (*this))
        return maxBytes;

    return compositeId->bytesWanted(minimum, maxBytes);
}

/*
 * this records actual bytes received.  always recorded, even if the
 * class is disabled - it's more efficient to just do it than to do all
 * the checks.
 */
void
DelayId::bytesIn(int qty)
{
    if (! (*this))
        return;

    compositeId->bytesIn(qty);
}

void
DelayId::delayRead(const AsyncCall::Pointer &aRead)
{
    assert (compositeId != nullptr);
    compositeId->delayRead(aRead);

}

#endif /* USE_DELAY_POOLS */

