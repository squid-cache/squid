/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef _SQUID_COMM_READ_H
#define _SQUID_COMM_READ_H

#include "base/AsyncCall.h"
#include "comm/forward.h"
#include "CommCalls.h"
#include "sbuf/forward.h"

namespace Comm
{

/**
 * Start monitoring for read.
 *
 * callback is scheduled when the read is possible,
 * or on file descriptor close.
 */
void Read(const Comm::ConnectionPointer &conn, AsyncCall::Pointer &callback);

/// whether the FD socket is being monitored for read
bool MonitorsRead(int fd);

/**
 * Perform a read(2) on a connection immediately.
 *
 * If params.size is non-zero will limit size of the read to either
 * the buffer free space or params.size, whichever is smallest.
 *
 * The returned flag is also placed in params.flag.
 *
 * \retval Comm::OK          data has been read and placed in buf, amount in params.size
 * \retval Comm::COMM_ERROR  an error occurred, the code is placed in params.xerrno
 * \retval Comm::INPROGRESS  unable to read at this time, or a minor error occurred
 * \retval Comm::ENDFILE     0-byte read has occurred.
 *                           Usually indicates the remote end has disconnected.
 */
Comm::Flag ReadNow(CommIoCbParams &params, SBuf &buf);

/// Cancel the read pending on FD. No action if none pending.
void ReadCancel(int fd, AsyncCall::Pointer &callback);

/// callback handler to process an FD which is available for reading
extern PF HandleRead;

/// maximum read delay for readers with limited lifetime
time_t MortalReadTimeout(const time_t startTime, const time_t lifetimeLimit);
} // namespace Comm

// Legacy API to be removed
void comm_read_base(const Comm::ConnectionPointer &conn, char *buf, int len, AsyncCall::Pointer &callback);
inline void comm_read(const Comm::ConnectionPointer &conn, char *buf, int len, AsyncCall::Pointer &callback)
{
    assert(buf != NULL);
    comm_read_base(conn, buf, len, callback);
}
void comm_read_cancel(int fd, IOCB *callback, void *data);

#endif /* _SQUID_COMM_READ_H */

