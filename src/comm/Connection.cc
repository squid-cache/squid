#include "config.h"
#include "cbdata.h"
#include "comm.h"
#include "comm/Connection.h"

Comm::Connection::Connection() :
        local(),
        remote(),
        _peer(NULL),
        peer_type(HIER_NONE),
        fd(-1),
        tos(0),
        flags(COMM_NONBLOCKING)
{}

Comm::Connection::Connection(Comm::Connection &c) :
        local(c.local),
        remote(c.remote),
        _peer(c._peer),
        peer_type(c.peer_type),
        fd(c.fd),
        tos(c.tos),
        flags(c.flags)
{}

Comm::Connection::~Connection()
{
    if (fd >= 0) {
        comm_close(fd);
    }
    if (_peer) {
        cbdataReferenceDone(_peer);
    }
}
