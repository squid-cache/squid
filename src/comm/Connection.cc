#include "squid.h"
#include "cbdata.h"
#include "comm.h"
#include "comm/Connection.h"
#include "fde.h"
#include "SquidTime.h"

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
        flags(COMM_NONBLOCKING),
        _peer(NULL)
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

    cbdataReferenceDone(_peer);
}

Comm::ConnectionPointer
Comm::Connection::copyDetails() const
{
    ConnectionPointer c = new Comm::Connection;

    c->local = local;
    c->remote = remote;
    c->peerType = peerType;
    c->tos = tos;
    c->flags = flags;

    // ensure FD is not open in the new copy.
    c->fd = -1;

    // ensure we have a cbdata reference to _peer not a straight ptr copy.
    c->_peer = cbdataReference(getPeer());

    return c;
}

void
Comm::Connection::close()
{
    if (isOpen()) {
        comm_close(fd);
        fd = -1;
        if (peer *p=getPeer())
            -- p->stats.conn_open;
    }
}

peer *
Comm::Connection::getPeer() const
{
    if (cbdataReferenceValid(_peer))
        return _peer;

    return NULL;
}

void
Comm::Connection::setPeer(peer *p)
{
    /* set to self. nothing to do. */
    if (getPeer() == p)
        return;

    cbdataReferenceDone(_peer);
    if (p) {
        _peer = cbdataReference(p);
    }
}
