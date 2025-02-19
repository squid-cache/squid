/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "ClientInfo.h"
#include "comm/Connection.h"
#include "comm/IoCallback.h"
#include "comm/Loops.h"
#include "comm/Write.h"
#include "CommCalls.h"
#include "fde.h"
#include "globals.h"

namespace Comm
{

// XXX: Add API to react to Squid_MaxFD changes.
/// Creates a new callback table using the current value of Squid_MaxFD.
/// \sa fde::Init()
static CbEntry *
MakeCallbackTable()
{
    // XXX: convert this to a std::map<> ?
    // XXX: Stop bypassing CbEntry-associated constructors! Refactor to use new() instead.
    const auto iocb_table = static_cast<CbEntry*>(xcalloc(Squid_MaxFD, sizeof(CbEntry)));
    for (int pos = 0; pos < Squid_MaxFD; ++pos) {
        iocb_table[pos].fd = pos;
        iocb_table[pos].readcb.type = IOCB_READ;
        iocb_table[pos].writecb.type = IOCB_WRITE;
    }
    return iocb_table;
}

} // namespace Comm

Comm::CbEntry &
Comm::ioCallbacks(const int fd)
{
    static const auto table = MakeCallbackTable();
    assert(fd < Squid_MaxFD);
    return table[fd];
}

/**
 * Configure Comm::Callback for I/O
 *
 * @param fd            filedescriptor
 * @param t             IO callback type (read or write)
 * @param cb            callback
 * @param buf           buffer, if applicable
 * @param func          freefunc, if applicable
 * @param sz            buffer size
 */
void
Comm::IoCallback::setCallback(Comm::iocb_type t, AsyncCall::Pointer &cb, char *b, FREE *f, int sz)
{
    assert(!active());
    assert(type == t);
    assert(cb != nullptr);

    callback = cb;
    buf = b;
    freefunc = f;
    size = sz;
    offset = 0;
}

void
Comm::IoCallback::selectOrQueueWrite()
{
#if USE_DELAY_POOLS
    if (BandwidthBucket *bucket = BandwidthBucket::SelectBucket(&fd_table[conn->fd])) {
        bucket->scheduleWrite(this);
        return;
    }
#endif

    SetSelect(conn->fd, COMM_SELECT_WRITE, Comm::HandleWrite, this, 0);
}

void
Comm::IoCallback::cancel(const char *reason)
{
    if (!active())
        return;

    callback->cancel(reason);
    callback = nullptr;
    reset();
}

void
Comm::IoCallback::reset()
{
    conn = nullptr;
    if (freefunc) {
        freefunc(buf);
        buf = nullptr;
        freefunc = nullptr;
    }
    xerrno = 0;

#if USE_DELAY_POOLS
    quotaQueueReserv = 0;
#endif
}

// Schedule the callback call and clear the callback
void
Comm::IoCallback::finish(Comm::Flag code, int xerrn)
{
    debugs(5, 3, "called for " << conn << " (" << code << ", " << xerrn << ")");
    assert(active());

    /* free data */
    if (freefunc && buf) {
        freefunc(buf);
        buf = nullptr;
        freefunc = nullptr;
    }

    if (callback != nullptr) {
        typedef CommIoCbParams Params;
        Params &params = GetCommParams<Params>(callback);
        if (conn != nullptr) params.fd = conn->fd; // for legacy write handlers...
        params.conn = conn;
        params.buf = buf;
        params.size = offset;
        params.flag = code;
        params.xerrno = xerrn;
        ScheduleCallHere(callback);
        callback = nullptr;
    }

    /* Reset for next round. */
    reset();
}

