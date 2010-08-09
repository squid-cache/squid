#ifndef SQUID_LISTENERSTATEDATA_H
#define SQUID_LISTENERSTATEDATA_H

#include "config.h"
#include "base/AsyncCall.h"
#include "comm.h"
#if HAVE_MAP
#include <map>
#endif

class ConnectionDetail;

namespace Comm
{

class ListenStateData
{

public:
    ListenStateData(int fd, AsyncCall::Pointer &call, bool accept_many);
    ListenStateData(const ListenStateData &r); // not implemented.
    ~ListenStateData();

    void subscribe(AsyncCall::Pointer &call);
    void acceptNext();
    void notify(int newfd, comm_err_t flag, const ConnectionDetail &details);

    int fd;

    /// errno code of the last accept() or listen() action if one occurred.
    int errcode;

    /// whether this socket is delayed and on the AcceptLimiter queue.
    int32_t isLimited;

private:
    /// Method to test if there are enough file escriptors to open a new client connection
    /// if not the accept() will be postponed
    static bool okToAccept();

    /// Method callback for whenever an FD is ready to accept a client connection.
    static void doAccept(int fd, void *data);

    void acceptOne();
    int oldAccept(ConnectionDetail &details);

    AsyncCall::Pointer theCallback;
    bool mayAcceptMore;

    void setListen();
};

}; // namespace Comm

#endif /* SQUID_LISTENERSTATEDATA_H */
