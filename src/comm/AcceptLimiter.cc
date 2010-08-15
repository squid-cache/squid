#include "config.h"
#include "comm/AcceptLimiter.h"
#include "comm/ConnAcceptor.h"
#include "comm/Connection.h"
#include "fde.h"

Comm::AcceptLimiter Comm::AcceptLimiter::Instance_;

Comm::AcceptLimiter &Comm::AcceptLimiter::Instance()
{
    return Instance_;
}

void
Comm::AcceptLimiter::defer(Comm::ConnAcceptor *afd)
{
    afd->isLimited++;
    debugs(5, 5, HERE << "FD " << afd->conn->fd << " x" << afd->isLimited);
    deferred.push_back(afd);
}

void
Comm::AcceptLimiter::kick()
{
    debugs(5, 5, HERE << " size=" << deferred.size());
    if (deferred.size() > 0 && fdNFree() >= RESERVED_FD) {
        debugs(5, 5, HERE << " doing one.");
        /* NP: shift() is equivalent to pop_front(). Giving us a FIFO queue. */
        ConnAcceptor *temp = deferred.shift();
        temp->isLimited--;
        temp->acceptNext();
    }
}
