/*
 * DEBUG: section 54    Interprocess Communication
 *
 */

#ifndef SQUID_IPC_SHARED_LISTEN_H
#define SQUID_IPC_SHARED_LISTEN_H

#include "base/AsyncCall.h"
#include "base/Subscription.h"

namespace Ipc
{

/// "shared listen" is when concurrent processes are listening on the same fd

/// Comm::ConnAcceptor parameters holder
/// all the details necessary to recreate a Comm::Connection and fde entry for the kid listener FD
class OpenListenerParams
{
public:
    OpenListenerParams();

    bool operator <(const OpenListenerParams &p) const; ///< useful for map<>

    // bits to re-create the fde entry
    int sock_type;
    int proto;
    int fdNote; ///< index into fd_note() comment strings

    // bits to re-create the listener Comm::Connection descriptor
    Ip::Address addr; ///< will be memset and memcopied
    int flags;

    /// handler to subscribe to Comm::ConnAcceptor when we get the response
    Subscription::Pointer handlerSubscription;
};

class TypedMsgHdr;

/// a request for a listen socket with given parameters
class SharedListenRequest
{
public:
    SharedListenRequest(); ///< from OpenSharedListen() which then sets public data
    explicit SharedListenRequest(const TypedMsgHdr &hdrMsg); ///< from recvmsg()
    void pack(TypedMsgHdr &hdrMsg) const; ///< prepare for sendmsg()

public:
    int requestorId; ///< kidId of the requestor

    OpenListenerParams params; ///< actual comm_open_sharedListen() parameters

    int mapId; ///< to map future response to the requestor's callback
};

/// a response to SharedListenRequest
class SharedListenResponse
{
public:
    SharedListenResponse(int fd, int errNo, int mapId);
    explicit SharedListenResponse(const TypedMsgHdr &hdrMsg); ///< from recvmsg()
    void pack(TypedMsgHdr &hdrMsg) const; ///< prepare for sendmsg()

public:
    int fd; ///< opened listening socket or -1
    int errNo; ///< errno value from comm_open_sharedListen() call
    int mapId; ///< to map future response to the requestor's callback
};

/// prepare and send SharedListenRequest to Coordinator
void JoinSharedListen(const OpenListenerParams &, AsyncCall::Pointer &);

/// process Coordinator response to SharedListenRequest
void SharedListenJoined(const SharedListenResponse &response);

} // namespace Ipc;

#endif /* SQUID_IPC_SHARED_LISTEN_H */
