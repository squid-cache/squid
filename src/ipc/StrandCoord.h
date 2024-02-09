/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_IPC_STRANDCOORD_H
#define SQUID_SRC_IPC_STRANDCOORD_H

#include "ipc/forward.h"
#include "ipc/Messages.h"
#include "ipc/QuestionerId.h"
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

/// an IPC message carrying StrandCoord
class StrandMessage
{
public:
    explicit StrandMessage(const StrandCoord &, QuestionerId);
    explicit StrandMessage(const TypedMsgHdr &);
    void pack(MessageType, TypedMsgHdr &) const;

    /// creates and sends StrandMessage to Coordinator
    static void NotifyCoordinator(MessageType, const char *tag);

    /// for Mine() tests
    QuestionerId intendedRecepient() const { return qid; }

public:
    StrandCoord strand; ///< messageType-specific coordinates (e.g., sender)

    /// For IPC requests/questions: The sender of this request.
    /// For IPC responses/answers: The sender of the corresponding request.
    QuestionerId qid;
};

} // namespace Ipc;

#endif /* SQUID_SRC_IPC_STRANDCOORD_H */

