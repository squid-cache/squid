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
Comm::AcceptLimiter::removeDead(const Comm::ConnAcceptor *afd)
{
    for (unsigned int i = 0; i < deferred.size() && afd->isLimited > 0; i++) {
        if (deferred[i] == afd) {
            deferred[i]->isLimited--;
            deferred[i] = NULL; // fast. kick() will skip empty entries later.
            debugs(5, 5, HERE << afd->conn << " x" << afd->isLimited);
        }
    }
}

void
Comm::AcceptLimiter::kick()
{
    // TODO: this could be optimized further with an iterator to search
    //       looking for first non-NULL, followed by dumping the first N
    //       with only one shift()/pop_ftron operation

    debugs(5, 5, HERE << " size=" << deferred.size());
    while (deferred.size() > 0 && fdNFree() >= RESERVED_FD) {
        /* NP: shift() is equivalent to pop_front(). Giving us a FIFO queue. */
        if ((ConnAcceptor *temp = deferred.shift()) != NULL) {
            debugs(5, 5, HERE << " doing one.");
            temp->isLimited--;
            temp->acceptNext();
            break;
        }
    }
}
