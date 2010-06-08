#ifndef SQUID_LISTENERSTATEDATA_H
#define SQUID_LISTENERSTATEDATA_H

#include "config.h"
#include "base/AsyncCall.h"
#include "comm/comm_err_t.h"
#include "comm/forward.h"

#if HAVE_MAP
#include <map>
#endif

namespace Comm
{

class Connection;

class ListenStateData
{

public:
    ListenStateData(int fd, AsyncCall::Pointer &call, bool accept_many);
    ListenStateData(const ListenStateData &r); // not implemented.
    ~ListenStateData();

    void subscribe(AsyncCall::Pointer &call);
    void acceptNext();
    void notify(int newfd, comm_err_t, int xerrno, Comm::ConnectionPointer);

    int fd;

    /// errno code if any happened so far.
    int errcode;

    /// whether this socket is delayed and on the AcceptLimiter queue.
    int32_t isLimited;

private:
    /// Method to test if there are enough file escriptors to open a new client connection
    /// if not the accept() will be postponed
    static bool okToAccept();

    /// Method callback for whenever an FD is ready to accept a client connection.
    static void doAccept(int fd, void *data);

    bool acceptOne();
    int oldAccept(Comm::Connection &details);

    AsyncCall::Pointer theCallback;
    bool mayAcceptMore;

    void setListen();
};

}; // namespace Comm

#endif /* SQUID_LISTENERSTATEDATA_H */
