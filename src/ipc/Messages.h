/*
 * $Id$
 *
 * DEBUG: section 54    Interprocess Communication
 *
 */

#ifndef SQUID_IPC_MESSAGES_H
#define SQUID_IPC_MESSAGES_H

#include <sys/types.h>

/** Declarations used by varios IPC messages */

namespace Ipc
{

class TypedMsgHdr;

/// message class identifier
typedef enum { mtNone = 0, mtRegistration,
               mtSharedListenRequest, mtSharedListenResponse
             } MessageType;

/// Strand location details
class StrandCoord
{
public:
    StrandCoord(); ///< unknown location
    StrandCoord(int akidId, pid_t aPid); ///< from registrant
    explicit StrandCoord(const TypedMsgHdr &hdrMsg); ///< from recvmsg()
    void pack(TypedMsgHdr &hdrMsg) const; ///< prepare for sendmsg()

public:
    int kidId; ///< internal Squid process number
    pid_t pid; ///< OS process or thread identifier
};

} // namespace Ipc;


#endif /* SQUID_IPC_MESSAGES_H */
