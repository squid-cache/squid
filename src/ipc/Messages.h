/*
 * $Id$
 *
 * DEBUG: section 54    Interprocess Communication
 *
 */

#ifndef SQUID_IPC_MESSAGES_H
#define SQUID_IPC_MESSAGES_H

#include <sys/types.h>
#include <sys/socket.h>

/// Declare IPC messages. These classes translate between high-level
/// information and low-level TypedMsgHdr (i.e., struct msghdr) buffers.

namespace Ipc
{

class TypedMsgHdr;

typedef enum { mtNone = 0, mtRegistration,
    mtSharedListenRequest, mtSharedListenResponse,
    mtDescriptorGet, mtDescriptorPut } MessageType;

/// Strand location details
class StrandCoord {
public:
    StrandCoord(); ///< unknown location
    StrandCoord(int akidId, pid_t aPid); ///< from registrant
    explicit StrandCoord(const TypedMsgHdr &hdrMsg); ///< from recvmsg()
    void pack(TypedMsgHdr &hdrMsg) const; ///< prepare for sendmsg()

public:
    int kidId; ///< internal Squid process number
    pid_t pid; ///< OS process or thread identifier
};

/// a [socket] descriptor information
class Descriptor
{
public:
    Descriptor(); ///< unknown descriptor
    Descriptor(int fromKid, int fd); ///< from descriptor sender or requestor
    explicit Descriptor(const TypedMsgHdr &hdrMsg); ///< from recvmsg()
    void pack(TypedMsgHdr &hdrMsg) const; ///< prepare for sendmsg()

public:
    int fromKid; /// the source of this message
    int fd; ///< raw descriptor value
};


} // namespace Ipc;


#endif /* SQUID_IPC_MESSAGES_H */
