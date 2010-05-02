/*
 * $Id$
 *
 * DEBUG: section 54    Interprocess Communication
 *
 */

#ifndef SQUID_IPC_SHARED_LISTEN_H
#define SQUID_IPC_SHARED_LISTEN_H

#include "base/AsyncCall.h"

namespace Ipc
{

/// "shared listen" is when concurrent processes are listening on the same fd

/// comm_open_listener() parameters holder
class OpenListenerParams
{
public:
    OpenListenerParams();

    bool operator <(const OpenListenerParams &p) const; ///< useful for map<>

    int sock_type;
    int proto;
    IpAddress addr; ///< will be memset and memcopied
    int flags;
    int fdNote; ///< index into fd_note() comment strings
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
extern void JoinSharedListen(const OpenListenerParams &, AsyncCall::Pointer &);

/// process Coordinator response to SharedListenRequest
extern void SharedListenJoined(const SharedListenResponse &response);

} // namespace Ipc;


#endif /* SQUID_IPC_SHARED_LISTEN_H */
