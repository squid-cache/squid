#include "config.h"
#include "comm/AcceptLimiter.h"
#include "comm/ListenStateData.h"
#include "fde.h"

Comm::AcceptLimiter Comm::AcceptLimiter::Instance_;

Comm::AcceptLimiter &Comm::AcceptLimiter::Instance()
{
    return Instance_;
}

void
Comm::AcceptLimiter::defer(Comm::ListenStateData *afd)
{
    afd->isLimited++;
    debugs(5, 5, HERE << "FD " << afd->fd << " x" << afd->isLimited);
    deferred.push_back(afd);
}

void
Comm::AcceptLimiter::kick()
{
    debugs(5, 5, HERE << " size=" << deferred.size());
    if (deferred.size() > 0 && fdNFree() >= RESERVED_FD) {
        debugs(5, 5, HERE << " doing one.");
        /* NP: shift() is equivalent to pop_front(). Giving us a FIFO queue. */
        ListenStateData *temp = deferred.shift();
        temp->isLimited--;
        temp->acceptNext();
    }
}
