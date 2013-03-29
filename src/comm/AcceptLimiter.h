#ifndef _SQUID_SRC_COMM_ACCEPT_LIMITER_H
#define _SQUID_SRC_COMM_ACCEPT_LIMITER_H

#include "Array.h"
#include "comm/TcpAcceptor.h"

namespace Comm
{

/**
 * FIFO Queue holding listener socket handlers which have been activated
 * ready to dupe their FD and accept() a new client connection.
 * But when doing so there were not enough FD available to handle the
 * new connection. These handlers are awaiting some FD to become free.
 *
 * defer - used only by Comm layer ConnAcceptor adding themselves when FD are limited.
 * removeDead - used only by Comm layer ConnAcceptor to remove themselves when dying.
 * kick - used by Comm layer when FD are closed.
 */
/* TODO this algorithm can be optimized further:
 *
 * 1) reduce overheads by only pushing one entry per port to the list?
 * use TcpAcceptor::isLimited as a flag whether to re-list when kick()'ing
 * or to NULL an entry while scanning the list for empty spaces.
 * Side effect: TcpAcceptor->kick() becomes allowed to pull off multiple accept()'s in bunches
 *
 * 2) re-implement as a list instead of vector?
 * storing head/tail pointers for fast push/pop and avoiding the whole shift() overhead
 */
class AcceptLimiter
{

public:
    /** retrieve the global instance of the queue. */
    static AcceptLimiter &Instance();

    /** delay accepting a new client connection. */
    void defer(const TcpAcceptor::Pointer &afd);

    /** remove all records of an acceptor. Only to be called by the ConnAcceptor::swanSong() */
    void removeDead(const TcpAcceptor::Pointer &afd);

    /** try to accept and begin processing any delayed client connections. */
    void kick();

private:
    static AcceptLimiter Instance_;

    /** FIFO queue */
    Vector<TcpAcceptor::Pointer> deferred_;
};

}; // namepace Comm

#endif /* _SQUID_SRC_COMM_ACCEPT_LIMITER_H */
