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
    debugs(5, 5, HERE << afd->conn << " x" << afd->isLimited);
    deferred.push_back(afd);
}

void
Comm::AcceptLimiter::removeDead(Comm::ConnAcceptor *afd)
{
    for (unsigned int i = 0; i < deferred.size() && afd->isLimited > 0; i++) {
        if (deferred[i] == afd) {
            deferred[i] = NULL;
            afd->isLimited--;
            debugs(5, 5, HERE << afd->conn << " x" << afd->isLimited);
        }
    }
}

void
Comm::AcceptLimiter::kick()
{
    debugs(5, 5, HERE << " size=" << deferred.size());
    while (deferred.size() > 0 && fdNFree() >= RESERVED_FD) {
        /* NP: shift() is equivalent to pop_front(). Giving us a FIFO queue. */
        ConnAcceptor *temp = deferred.shift();
        if (temp != NULL) {
            debugs(5, 5, HERE << " doing one.");
            temp->isLimited--;
            temp->acceptNext();
            break;
        }
    }
}
