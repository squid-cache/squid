
/*
 * $Id$
 *
 * DEBUG: section 77    Delay Pools
 * AUTHOR: Robert Collins <robertc@squid-cache.org>
 * Based upon original delay pools code by
 *   David Luyer <david@luyer.net>
 *
 * SQUID Web Proxy Cache          http://www.squid-cache.org/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from
 *  the Internet community; see the CONTRIBUTORS file for full
 *  details.   Many organizations have provided support for Squid's
 *  development; see the SPONSORS file for full details.  Squid is
 *  Copyrighted (C) 2001 by the Regents of the University of
 *  California; see the COPYRIGHT file for full details.  Squid
 *  incorporates software developed and/or copyrighted by other
 *  sources; see the CREDITS file for full details.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111, USA.
 *
 *
 * Copyright (c) 2003, Robert Collins <robertc@squid-cache.org>
 */

#include "config.h"

/* MS Visual Studio Projects are monolithic, so we need the following
 * #if to exclude the delay pools code from compile process when not needed.
 */
#if DELAY_POOLS

#include "squid.h"
#include "DelayId.h"
#include "client_side_request.h"
#include "acl/FilledChecklist.h"
#include "DelayPools.h"
#include "DelayPool.h"
#include "HttpRequest.h"
#include "CommRead.h"

DelayId::DelayId () : pool_ (0), compositeId(NULL), markedAsNoDelay(false)
{}

DelayId::DelayId (unsigned short aPool) :
        pool_ (aPool), compositeId (NULL), markedAsNoDelay (false)
{
    debugs(77, 3, "DelayId::DelayId: Pool " << aPool << "u");
}

DelayId::~DelayId ()
{}

void
DelayId::compositePosition(DelayIdComposite::Pointer newPosition)
{
    compositeId = newPosition;
}

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
    return pool_ || compositeId.getRaw();
}

/* create a delay Id for a given request */
DelayId
DelayId::DelayClient(ClientHttpRequest * http)
{
    HttpRequest *r;
    unsigned short pool;
    assert(http);
    r = http->request;

    if (r->client_addr.IsNoAddr()) {
        debugs(77, 2, "delayClient: WARNING: Called with 'NO_ADDR' address, ignoring");
        return DelayId();
    }

    for (pool = 0; pool < DelayPools::pools(); pool++) {

        /* pools require explicit 'allow' to assign a client into them */
        if (!DelayPools::delay_data[pool].access) {
            debugs(77, DBG_IMPORTANT, "delay_pool " << pool <<
                   " has no delay_access configured. This means that no clients will ever use it.");
            continue;
        }

        ACLFilledChecklist ch(DelayPools::delay_data[pool].access, r, NULL);
#if FOLLOW_X_FORWARDED_FOR
        if (Config.onoff.delay_pool_uses_indirect_client)
            ch.src_addr = r->indirect_client_addr;
        else
#endif /* FOLLOW_X_FORWARDED_FOR */
            ch.src_addr = r->client_addr;
        ch.my_addr = r->my_addr;

        if (http->getConn() != NULL)
            ch.conn(http->getConn());

        if (DelayPools::delay_data[pool].theComposite().getRaw() && ch.fastCheck()) {

            DelayId result (pool + 1);
            CompositePoolNode::CompositeSelectionDetails details;
            details.src_addr = ch.src_addr;
            details.user = r->auth_user_request;
            details.tag = r->tag;
            result.compositePosition(DelayPools::delay_data[pool].theComposite()->id(details));
            return result;
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
    /* unlimited */

    if (! (*this) || markedAsNoDelay)
        return max(minimum, maximum);

    /* limited */
    int nbytes = max(minimum, maximum);

    if (compositeId != NULL)
        nbytes = compositeId->bytesWanted(minimum, nbytes);

    return nbytes;
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

    if (markedAsNoDelay)
        return;

    assert ((unsigned short)(pool() - 1) != 0xFFFF);

    if (compositeId != NULL)
        compositeId->bytesIn(qty);
}

void
DelayId::delayRead(DeferredRead const &aRead)
{
    assert (compositeId != NULL);
    compositeId->delayRead(aRead);

}

#endif /* DELAY_POOLS */
