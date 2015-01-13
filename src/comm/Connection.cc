/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "CachePeer.h"
#include "cbdata.h"
#include "comm.h"
#include "comm/Connection.h"
#include "fde.h"
#include "neighbors.h"
#include "SquidTime.h"

class CachePeer;
bool
Comm::IsConnOpen(const Comm::ConnectionPointer &conn)
{
    return conn != NULL && conn->isOpen();
}

Comm::Connection::Connection() :
    local(),
    remote(),
    peerType(HIER_NONE),
    fd(-1),
    tos(0),
    nfmark(0),
    flags(COMM_NONBLOCKING),
    peer_(NULL),
    startTime_(squid_curtime)
{
    *rfc931 = 0; // quick init the head. the rest does not matter.
}

static int64_t lost_conn = 0;
Comm::Connection::~Connection()
{
    if (fd >= 0) {
        debugs(5, 4, "BUG #3329: Orphan Comm::Connection: " << *this);
        debugs(5, 4, "NOTE: " << ++lost_conn << " Orphans since last started.");
        close();
    }

    cbdataReferenceDone(peer_);
}

Comm::ConnectionPointer
Comm::Connection::copyDetails() const
{
    ConnectionPointer c = new Comm::Connection;

    c->setAddrs(local, remote);
    c->peerType = peerType;
    c->tos = tos;
    c->nfmark = nfmark;
    c->flags = flags;
    c->startTime_ = startTime_;

    // ensure FD is not open in the new copy.
    c->fd = -1;

    // ensure we have a cbdata reference to peer_ not a straight ptr copy.
    c->peer_ = cbdataReference(getPeer());

    return c;
}

void
Comm::Connection::close()
{
    if (isOpen()) {
        comm_close(fd);
        fd = -1;
        if (CachePeer *p=getPeer())
            peerConnClosed(p);
    }
}

CachePeer *
Comm::Connection::getPeer() const
{
    if (cbdataReferenceValid(peer_))
        return peer_;

    return NULL;
}

void
Comm::Connection::setPeer(CachePeer *p)
{
    /* set to self. nothing to do. */
    if (getPeer() == p)
        return;

    cbdataReferenceDone(peer_);
    if (p) {
        peer_ = cbdataReference(p);
    }
}

