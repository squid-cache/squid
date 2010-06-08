#include "config.h"
#include "cbdata.h"
#include "comm.h"
#include "comm/Connection.h"

Comm::Connection::Connection() :
        local(),
        remote(),
        peer_type(HIER_NONE),
        fd(-1),
        tos(0),
        flags(COMM_NONBLOCKING),
        _peer(NULL)
{}

Comm::Connection::Connection(const Comm::Connection &c) :
        local(c.local),
        remote(c.remote),
        peer_type(c.peer_type),
        fd(c.fd),
        tos(c.tos),
        flags(c.flags)
{
    _peer = cbdataReference(c._peer);
}

const Comm::Connection &
Comm::Connection::operator =(const Comm::Connection &c)
{
    memcpy(this, &c, sizeof(Comm::Connection));

    /* ensure we have a cbdata reference to _peer not a straight ptr copy. */
    _peer = cbdataReference(c._peer);

    return *this;
}

Comm::Connection::~Connection()
{
    if (fd >= 0) {
        comm_close(fd);
    }
    if (_peer) {
        cbdataReferenceDone(_peer);
    }
}

void
Comm::Connection::setPeer(peer *p)
{
    /* set to self. nothing to do. */
    if (_peer == p)
        return;

    /* clear any previous ptr */
    if (_peer) {
        cbdataReferenceDone(_peer);
        _peer = NULL;
    }

   /* set the new one (unless it is NULL */
   if (p) {
        _peer = cbdataReference(p);
   }
}
