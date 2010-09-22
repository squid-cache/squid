#include "config.h"
#include "cbdata.h"
#include "comm.h"
#include "comm/Connection.h"

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
{}

Comm::Connection::~Connection()
{
    close();
    if (getPeer())
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
        if (getPeer())
            getPeer()->stats.conn_open--;
    }
}

peer * const
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

    /* clear any previous ptr */
    if (getPeer())
        cbdataReferenceDone(_peer);

    /* set the new one (unless it is NULL */
    if (p) {
        _peer = cbdataReference(p);
    }
}
