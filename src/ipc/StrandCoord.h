/*
 * $Id$
 *
 */

#ifndef SQUID_IPC_STRAND_COORD_H
#define SQUID_IPC_STRAND_COORD_H

#include "ipc/forward.h"
#include <sys/types.h>

namespace Ipc
{

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

#endif /* SQUID_IPC_STRAND_COORD_H */
