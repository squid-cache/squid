/*
 * AUTHOR: Robert Collins
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
 * Copyright (c) 2003, Robert Collins <robertc@squid-cache.org>
 */

#ifndef   SQUID_PEERSELECTSTATE_H
#define   SQUID_PEERSELECTSTATE_H

#include "acl/Checklist.h"
#include "Array.h"
#include "cbdata.h"
#include "comm/forward.h"
#include "hier_code.h"
#include "PingData.h"
#include "ip/Address.h"

class HttpRequest;
class StoreEntry;
class ErrorState;

typedef void PSC(Comm::ConnectionList *, ErrorState *, void *);

void peerSelect(Comm::ConnectionList *, HttpRequest *, StoreEntry *, PSC *, void *data);
void peerSelectInit(void);

/**
 * A CachePeer which has been selected as a possible destination.
 * Listed as pointers here so as to prevent duplicates being added but will
 * be converted to a set of IP address path options before handing back out
 * to the caller.
 *
 * Certain connection flags and outgoing settings will also be looked up and
 * set based on the received request and CachePeer settings before handing back.
 */
class FwdServer
{
public:
    CachePeer *_peer;                /* NULL --> origin server */
    hier_code code;
    FwdServer *next;
};

class ps_state
{

public:
    void *operator new(size_t);
    ps_state();

    // Produce a URL for display identifying the transaction we are
    // trying to locate a peer for.
    const char * url() const;

    HttpRequest *request;
    StoreEntry *entry;
    allow_t always_direct;
    allow_t never_direct;
    int direct;   // TODO: fold always_direct/never_direct/prefer_direct into this now that ACL can do a multi-state result.
    PSC *callback;
    void *callback_data;
    ErrorState *lastError;

    Comm::ConnectionList *paths;    ///< the callers paths array. to be filled with our final results.
    FwdServer *servers;    ///< temporary linked list of peers we will pass back.

    /*
     * Why are these Ip::Address instead of CachePeer *?  Because a
     * CachePeer structure can become invalid during the CachePeer selection
     * phase, specifically after a reconfigure.  Thus we need to lookup
     * the CachePeer * based on the address when we are finally ready to
     * reference the CachePeer structure.
     */

    Ip::Address first_parent_miss;

    Ip::Address closest_parent_miss;
    /*
     * ->hit can be CachePeer* because it should only be
     * accessed during the thread when it is set
     */
    CachePeer *hit;
    peer_t hit_type;
    ping_data ping;
    ACLChecklist *acl_checklist;
private:
    CBDATA_CLASS(ps_state);
};

#endif /* SQUID_PEERSELECTSTATE_H */
