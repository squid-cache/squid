/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "base/TextException.h"
#include "ipc/QuestionerId.h"
#include "ipc/TypedMsgHdr.h"
#include "sbuf/Stream.h"

#include <iostream>

Ipc::QuestionerId
Ipc::MyQuestionerId()
{
    static const QuestionerId qid(getpid());
    return qid;
}

void
Ipc::QuestionerId::pack(TypedMsgHdr &hdrMsg) const
{
    hdrMsg.putPod(pid);
}

void
Ipc::QuestionerId::unpack(const TypedMsgHdr &hdrMsg)
{
    hdrMsg.getPod(pid);
}

void
Ipc::QuestionerId::rejectAnswerIfStale() const
{
    const auto myPid = MyQuestionerId().pid;
    if (myPid != pid) {
        throw TextException(ToSBuf("received answer to an IPC question asked by process ", pid,
                                   Debug::Extra, "my process PID: ", myPid), Here());
    }
}

void
Ipc::QuestionerId::print(std::ostream &os) const
{
    os << pid;
}

