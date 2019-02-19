/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef _SQUID_COMM_IOCALLBACK_H
#define _SQUID_COMM_IOCALLBACK_H

#include "base/AsyncCall.h"
#include "comm/Flag.h"
#include "comm/forward.h"
#include "mem/forward.h"
#include "sbuf/forward.h"

namespace Comm
{

/// Type of IO callbacks the Comm layer deals with.
typedef enum {
    IOCB_NONE,
    IOCB_READ,
    IOCB_WRITE
} iocb_type;

/// Details about a particular Comm IO callback event.
class IoCallback
{
public:
    iocb_type type;
    Comm::ConnectionPointer conn;
    AsyncCall::Pointer callback;
    char *buf;
    FREE *freefunc;
    int size;
    int offset;
    Comm::Flag errcode;
    int xerrno;
#if USE_DELAY_POOLS
    unsigned int quotaQueueReserv; ///< reservation ID from CommQuotaQueue
#endif

    bool active() const { return callback != NULL; }
    void setCallback(iocb_type type, AsyncCall::Pointer &cb, char *buf, FREE *func, int sz);

    /// called when fd needs to write but may need to wait in line for its quota
    void selectOrQueueWrite();

    /// Actively cancel the given callback
    void cancel(const char *reason);

    /// finish the IO operation imediately and schedule the callback with the current state.
    void finish(Comm::Flag code, int xerrn);

private:
    void reset();
};

/// Entry nodes for the IO callback table: iocb_table
/// Keyed off the FD which the event applies to.
class CbEntry
{
public:
    int fd;
    IoCallback  readcb;
    IoCallback  writecb;
};

/// Table of scheduled IO events which have yet to be processed ??
/// Callbacks which might be scheduled in future are stored in fd_table.
extern CbEntry *iocb_table;

void CallbackTableInit();
void CallbackTableDestruct();

#define COMMIO_FD_READCB(fd)    (&Comm::iocb_table[(fd)].readcb)
#define COMMIO_FD_WRITECB(fd)   (&Comm::iocb_table[(fd)].writecb)

} // namespace Comm

#endif /* _SQUID_COMM_IOCALLBACK_H */

