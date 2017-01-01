/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "comm/Flag.h"
#include "CommCalls.h"
#include "HttpControlMsg.h"

void
HttpControlMsgSink::doneWithControlMsg()
{
    if (cbControlMsgSent) {
        ScheduleCallHere(cbControlMsgSent);
        cbControlMsgSent = nullptr;
    }
}

/// called when we wrote the 1xx response
void
HttpControlMsgSink::wroteControlMsg(const CommIoCbParams &params)
{
    if (params.flag == Comm::ERR_CLOSING)
        return;

    if (params.flag == Comm::OK) {
        doneWithControlMsg();
        return;
    }

    debugs(33, 3, "1xx writing failed: " << xstrerr(params.xerrno));
    // no error notification: see HttpControlMsg.h for rationale and
    // note that some errors are detected elsewhere (e.g., close handler)

    // close on 1xx errors to be conservative and to simplify the code
    // (if we do not close, we must notify the source of a failure!)
    params.conn->close();

    // XXX: writeControlMsgAndCall() should handle writer-specific writing
    // results, including errors and then call us with success/failure outcome.
}

