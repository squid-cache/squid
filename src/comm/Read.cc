/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 05    Socket Functions */

#include "squid.h"
#include "comm.h"
#include "comm/IoCallback.h"
#include "comm/Loops.h"
#include "comm/Read.h"
#include "comm_internal.h"
#include "CommCalls.h"
#include "Debug.h"
#include "fd.h"
#include "fde.h"
#include "sbuf/SBuf.h"
#include "StatCounters.h"

// Does comm check this fd for read readiness?
// Note that when comm is not monitoring, there can be a pending callback
// call, which may resume comm monitoring once fired.
bool
Comm::MonitorsRead(int fd)
{
    assert(isOpen(fd) && COMMIO_FD_READCB(fd) != NULL);
    // Being active is usually the same as monitoring because we always
    // start monitoring the FD when we configure Comm::IoCallback for I/O
    // and we usually configure Comm::IoCallback for I/O when we starting
    // monitoring a FD for reading.
    return COMMIO_FD_READCB(fd)->active();
}

void
Comm::Read(const Comm::ConnectionPointer &conn, AsyncCall::Pointer &callback)
{
    // TODO: move comm_read_base() internals into here
    // when comm_read() char* API is no longer needed
    comm_read_base(conn, NULL, 0, callback);
}

/**
 * Queue a read.
 * If a buffer is given the callback is scheduled when the read
 * completes, on error, or on file descriptor close.
 *
 * If no buffer (NULL) is given the callback is scheduled when
 * the socket FD is ready for a read(2)/recv(2).
 */
void
comm_read_base(const Comm::ConnectionPointer &conn, char *buf, int size, AsyncCall::Pointer &callback)
{
    debugs(5, 5, "comm_read, queueing read for " << conn << "; asynCall " << callback);

    /* Make sure we are open and not closing */
    assert(Comm::IsConnOpen(conn));
    assert(!fd_table[conn->fd].closing());
    Comm::IoCallback *ccb = COMMIO_FD_READCB(conn->fd);

    // Make sure we are either not reading or just passively monitoring.
    // Active/passive conflicts are OK and simply cancel passive monitoring.
    if (ccb->active()) {
        // if the assertion below fails, we have an active comm_read conflict
        assert(fd_table[conn->fd].halfClosedReader != NULL);
        commStopHalfClosedMonitor(conn->fd);
        assert(!ccb->active());
    }
    ccb->conn = conn;

    /* Queue the read */
    ccb->setCallback(Comm::IOCB_READ, callback, (char *)buf, NULL, size);
    Comm::SetSelect(conn->fd, COMM_SELECT_READ, Comm::HandleRead, ccb, 0);
}

Comm::Flag
Comm::ReadNow(CommIoCbParams &params, SBuf &buf)
{
    /* Attempt a read */
    ++ statCounter.syscalls.sock.reads;
    SBuf::size_type sz = buf.spaceSize();
    if (params.size > 0 && params.size < sz)
        sz = params.size;
    char *inbuf = buf.rawSpace(sz);
    errno = 0;
    const int retval = FD_READ_METHOD(params.conn->fd, inbuf, sz);
    params.xerrno = errno;

    debugs(5, 3, params.conn << ", size " << sz << ", retval " << retval << ", errno " << params.xerrno);

    if (retval > 0) { // data read most common case
        buf.append(inbuf, retval);
        fd_bytes(params.conn->fd, retval, FD_READ);
        params.flag = Comm::OK;
        params.size = retval;

    } else if (retval == 0) { // remote closure (somewhat less) common
        // Note - read 0 == socket EOF, which is a valid read.
        params.flag = Comm::ENDFILE;

    } else if (retval < 0) { // connection errors are worst-case
        debugs(5, 3, params.conn << " Comm::COMM_ERROR: " << xstrerr(params.xerrno));
        if (ignoreErrno(params.xerrno))
            params.flag =  Comm::INPROGRESS;
        else
            params.flag =  Comm::COMM_ERROR;
    }

    return params.flag;
}

/**
 * Handle an FD which is ready for read(2).
 *
 * If there is no provided buffer to fill call the callback.
 *
 * Otherwise attempt a read into the provided buffer.
 * If the read attempt succeeds or fails, call the callback.
 * Else, wait for another IO notification.
 */
void
Comm::HandleRead(int fd, void *data)
{
    Comm::IoCallback *ccb = (Comm::IoCallback *) data;

    assert(data == COMMIO_FD_READCB(fd));
    assert(ccb->active());

    // Without a buffer, just call back.
    // The callee may ReadMore() to get the data.
    if (!ccb->buf) {
        ccb->finish(Comm::OK, 0);
        return;
    }

    /* For legacy callers : Attempt a read */
    // Keep in sync with Comm::ReadNow()!
    ++ statCounter.syscalls.sock.reads;
    int xerrno = errno = 0;
    int retval = FD_READ_METHOD(fd, ccb->buf, ccb->size);
    xerrno = errno;
    debugs(5, 3, "FD " << fd << ", size " << ccb->size << ", retval " << retval << ", errno " << xerrno);

    /* See if we read anything */
    /* Note - read 0 == socket EOF, which is a valid read */
    if (retval >= 0) {
        fd_bytes(fd, retval, FD_READ);
        ccb->offset = retval;
        ccb->finish(Comm::OK, 0);
        return;
    } else if (retval < 0 && !ignoreErrno(xerrno)) {
        debugs(5, 3, "comm_read_try: scheduling Comm::COMM_ERROR");
        ccb->offset = 0;
        ccb->finish(Comm::COMM_ERROR, xerrno);
        return;
    };

    /* Nope, register for some more IO */
    Comm::SetSelect(fd, COMM_SELECT_READ, Comm::HandleRead, data, 0);
}

/**
 * Cancel a pending read. Assert that we have the right parameters,
 * and that there are no pending read events!
 *
 * XXX: We do not assert that there are no pending read events and
 * with async calls it becomes even more difficult.
 * The whole interface should be reworked to do callback->cancel()
 * instead of searching for places where the callback may be stored and
 * updating the state of those places.
 *
 * AHC Don't call the comm handlers?
 */
void
comm_read_cancel(int fd, IOCB *callback, void *data)
{
    if (!isOpen(fd)) {
        debugs(5, 4, "fails: FD " << fd << " closed");
        return;
    }

    Comm::IoCallback *cb = COMMIO_FD_READCB(fd);
    // TODO: is "active" == "monitors FD"?
    if (!cb->active()) {
        debugs(5, 4, "fails: FD " << fd << " inactive");
        return;
    }

    typedef CommCbFunPtrCallT<CommIoCbPtrFun> Call;
    Call *call = dynamic_cast<Call*>(cb->callback.getRaw());
    if (!call) {
        debugs(5, 4, "fails: FD " << fd << " lacks callback");
        return;
    }

    call->cancel("old comm_read_cancel");

    typedef CommIoCbParams Params;
    const Params &params = GetCommParams<Params>(cb->callback);

    /* Ok, we can be reasonably sure we won't lose any data here! */
    assert(call->dialer.handler == callback);
    assert(params.data == data);

    /* Delete the callback */
    cb->cancel("old comm_read_cancel");

    /* And the IO event */
    Comm::SetSelect(fd, COMM_SELECT_READ, NULL, NULL, 0);
}

void
Comm::ReadCancel(int fd, AsyncCall::Pointer &callback)
{
    callback->cancel("comm_read_cancel");

    if (!isOpen(fd)) {
        debugs(5, 4, "fails: FD " << fd << " closed");
        return;
    }

    Comm::IoCallback *cb = COMMIO_FD_READCB(fd);

    if (!cb->active()) {
        debugs(5, 4, "fails: FD " << fd << " inactive");
        return;
    }

    AsyncCall::Pointer call = cb->callback;

    /* Ok, we can be reasonably sure we won't lose any data here! */
    assert(call == callback);

    /* Delete the callback */
    cb->cancel("comm_read_cancel");

    /* And the IO event */
    Comm::SetSelect(fd, COMM_SELECT_READ, NULL, NULL, 0);
}

