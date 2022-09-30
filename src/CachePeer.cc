/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "acl/FilledChecklist.h"
#include "acl/Gadgets.h"
#include "CachePeer.h"
#include "defines.h"
#include "neighbors.h"
#include "NeighborTypeDomainList.h"
#include "pconn.h"
#include "PeerPoolMgr.h"
#include "SquidConfig.h"

CBDATA_CLASS_INIT(CachePeer);

CachePeer::~CachePeer()
{
    xfree(name);
    xfree(host);

    while (NeighborTypeDomainList *l = typelist) {
        typelist = l->next;
        xfree(l->domain);
        xfree(l);
    }

    aclDestroyAccessList(&access);

#if USE_CACHE_DIGESTS
    cbdataReferenceDone(digest);
    xfree(digest_url);
#endif

    delete next;

    xfree(login);

    delete standby.pool;

    // the mgr job will notice that its owner is gone and stop
    PeerPoolMgr::Checkpoint(standby.mgr, "peer gone");

    xfree(domain);
}

time_t
CachePeer::connectTimeout() const
{
    if (connect_timeout_raw > 0)
        return connect_timeout_raw;
    return Config.Timeout.peer_connect;
}

void
CachePeer::peerConnectFailed(ACLFilledChecklist *checklist)
{
    debugs(15, DBG_IMPORTANT, "ERROR: TCP connection to " << host << "/" << http_port << " failed");

    if (checklist && !checklist->fastCheck().allowed())
        return;

    peerConnectFailedSilent();
}

void
CachePeer::peerConnectFailedSilent()
{
    stats.last_connect_failure = squid_curtime;

    if (!tcp_up) {
        debugs(15, 2, "TCP connection to " << host << "/" << http_port <<
               " dead");
        return;
    }

    --tcp_up;

    if (!tcp_up) {
        debugs(15, DBG_IMPORTANT, "Detected DEAD " << neighborTypeStr(this) << ": " << name);
        stats.logged_state = PEER_DEAD;
    }
}
