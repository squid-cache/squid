/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_IPC_STRAND_COORD_H
#define SQUID_IPC_STRAND_COORD_H

#include "ipc/forward.h"
#include "SquidString.h"

namespace Ipc
{

/// Strand location details
class StrandCoord
{
public:
    StrandCoord(); ///< unknown location
    StrandCoord(int akidId, pid_t aPid);

    void pack(TypedMsgHdr &hdrMsg) const; ///< prepare for sendmsg()
    void unpack(const TypedMsgHdr &hdrMsg); ///< from recvmsg()

public:
    int kidId; ///< internal Squid process number
    pid_t pid; ///< OS process or thread identifier

    String tag; ///< optional unique well-known key (e.g., cache_dir path)
};

/// strand registration with Coordinator (also used as an ACK)
class HereIamMessage
{
public:
    explicit HereIamMessage(const StrandCoord &strand); ///< from registrant
    explicit HereIamMessage(const TypedMsgHdr &hdrMsg); ///< from recvmsg()
    void pack(TypedMsgHdr &hdrMsg) const; ///< prepare for sendmsg()

public:
    StrandCoord strand; ///< registrant coordinates and related details
};

} // namespace Ipc;

#endif /* SQUID_IPC_STRAND_COORD_H */

