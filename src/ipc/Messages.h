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

typedef enum { mtNone = 0, mtRegistration, mtDescriptor } MessageType;

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
    explicit Descriptor(int fd); ///< from descriptor sender
	explicit Descriptor(const TypedMsgHdr &hdrMsg); ///< from recvmsg()
	void pack(TypedMsgHdr &hdrMsg) const; ///< prepare for sendmsg()

public:
    int fd; ///< raw descriptor value
};


} // namespace Ipc;


#endif /* SQUID_IPC_MESSAGES_H */
