#include "squid.h"
#include "ClientInfo.h"
#include "comm/Connection.h"
#include "comm/IoCallback.h"
#include "comm/Loops.h"
#include "comm/Write.h"
#include "CommCalls.h"
#include "fde.h"
#include "globals.h"

Comm::CbEntry *Comm::iocb_table;

void
Comm::CallbackTableInit()
{
    // XXX: convert this to a std::map<> ?
    iocb_table = static_cast<CbEntry*>(xcalloc(Squid_MaxFD, sizeof(CbEntry)));
    for (int pos = 0; pos < Squid_MaxFD; ++pos) {
        iocb_table[pos].fd = pos;
        iocb_table[pos].readcb.type = IOCB_READ;
        iocb_table[pos].writecb.type = IOCB_WRITE;
    }
}

void
Comm::CallbackTableDestruct()
{
    // release any Comm::Connections being held.
    for (int pos = 0; pos < Squid_MaxFD; ++pos) {
        iocb_table[pos].readcb.conn = NULL;
        iocb_table[pos].writecb.conn = NULL;
    }
    safe_free(iocb_table);
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
    assert(cb != NULL);

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
    // stand in line if there is one
    if (ClientInfo *clientInfo = fd_table[conn->fd].clientInfo) {
        if (clientInfo->writeLimitingActive) {
            quotaQueueReserv = clientInfo->quotaEnqueue(conn->fd);
            clientInfo->kickQuotaQueue();
            return;
        }
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
    callback = NULL;
    reset();
}

void
Comm::IoCallback::reset()
{
    conn = NULL;
    if (freefunc) {
        freefunc(buf);
        buf = NULL;
        freefunc = NULL;
    }
    xerrno = 0;

#if USE_DELAY_POOLS
    quotaQueueReserv = 0;
#endif
}

// Schedule the callback call and clear the callback
void
Comm::IoCallback::finish(comm_err_t code, int xerrn)
{
    debugs(5, 3, HERE << "called for " << conn << " (" << code << ", " << xerrno << ")");
    assert(active());

    /* free data */
    if (freefunc) {
        freefunc(buf);
        buf = NULL;
        freefunc = NULL;
    }

    if (callback != NULL) {
        typedef CommIoCbParams Params;
        Params &params = GetCommParams<Params>(callback);
        if (conn != NULL) params.fd = conn->fd; // for legacy write handlers...
        params.conn = conn;
        params.buf = buf;
        params.size = offset;
        params.flag = code;
        params.xerrno = xerrn;
        ScheduleCallHere(callback);
        callback = NULL;
    }

    /* Reset for next round. */
    reset();
}
