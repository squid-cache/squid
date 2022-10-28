/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
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
#include "sbuf/Stream.h"
#include "SquidConfig.h"
#include "util.h"

CBDATA_CLASS_INIT(CachePeer);

CachePeer::CachePeer(const SBuf &hostAsConfigured):
    host(SBufToCstring(hostAsConfigured))
{
    Tolower(host);
    identifyAs(hostAsConfigured);
}

CachePeer::~CachePeer()
{
    // idAsCstring_ memory is managed by id_

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

void
CachePeer::rename(const SBuf &newName)
{
    name_ = newName;
    identifyAs(name_.value());
}

void
CachePeer::forgetName()
{
    name_.reset();
    identifyAsHostname();
}

void
CachePeer::finalizeName()
{
    if (!name_.has_value())
        identifyAsHostname();
}

void
CachePeer::identifyAs(const SBuf &newId)
{
    id_ = newId;
    idAsCstring_ = id_.c_str();
}

void
CachePeer::identifyAsHostname()
{
    identifyAs(SBuf(host));
}

time_t
CachePeer::connectTimeout() const
{
    if (connect_timeout_raw > 0)
        return connect_timeout_raw;
    return Config.Timeout.peer_connect;
}

std::ostream &
operator <<(std::ostream &os, const CachePeer &p)
{
    return os << p.id();
}
