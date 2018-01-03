/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "acl/Gadgets.h"
#include "CachePeer.h"
#include "defines.h"
#include "NeighborTypeDomainList.h"
#include "pconn.h"
#include "PeerPoolMgr.h"

CBDATA_CLASS_INIT(CachePeer);

CachePeer::CachePeer() :
    index(0),
    name(NULL),
    host(NULL),
    type(PEER_NONE),
    http_port(CACHE_HTTP_PORT),
    typelist(NULL),
    access(NULL),
    weight(1),
    basetime(0),
#if USE_CACHE_DIGESTS
    digest(NULL),
    digest_url(NULL),
#endif
    tcp_up(0),
    reprobe(false),
    n_addresses(0),
    rr_count(0),
    next(NULL),
    testing_now(false),
    login(NULL),
    connect_timeout_raw(0),
    connect_fail_limit(0),
    max_conn(0),
    domain(NULL),
    front_end_https(0),
    connection_auth(2 /* auto */)
{
    memset(&stats, 0, sizeof(stats));
    stats.logged_state = PEER_ALIVE;

    memset(&icp, 0, sizeof(icp));
    icp.port = CACHE_ICP_PORT;
    icp.version = ICP_VERSION_CURRENT;

#if USE_HTCP
    memset(&htcp, 0, sizeof(htcp));
#endif
    memset(&options, 0, sizeof(options));
    memset(&mcast, 0, sizeof(mcast));
    memset(&carp, 0, sizeof(carp));
#if USE_AUTH
    memset(&userhash, 0, sizeof(userhash));
#endif
    memset(&sourcehash, 0, sizeof(sourcehash));

    standby.pool = NULL;
    standby.limit = 0;
    standby.waitingForClose = false;
}

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

