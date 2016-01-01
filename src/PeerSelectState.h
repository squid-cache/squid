/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef   SQUID_PEERSELECTSTATE_H
#define   SQUID_PEERSELECTSTATE_H

#include "AccessLogEntry.h"
#include "acl/Checklist.h"
#include "cbdata.h"
#include "comm/forward.h"
#include "hier_code.h"
#include "ip/Address.h"
#include "PingData.h"

class HttpRequest;
class StoreEntry;
class ErrorState;

typedef void PSC(Comm::ConnectionList *, ErrorState *, void *);

void peerSelect(Comm::ConnectionList *, HttpRequest *, AccessLogEntry::Pointer const&, StoreEntry *, PSC *, void *data);
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
    ps_state();
    ~ps_state();

    // Produce a URL for display identifying the transaction we are
    // trying to locate a peer for.
    const char * url() const;

    HttpRequest *request;
    AccessLogEntry::Pointer al; ///< info for the future access.log entry
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
    CBDATA_CLASS2(ps_state);
};

#endif /* SQUID_PEERSELECTSTATE_H */

