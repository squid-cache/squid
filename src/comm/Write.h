/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef _SQUID_COMM_IOWRITE_H
#define _SQUID_COMM_IOWRITE_H

#include "base/AsyncCall.h"
#include "comm/forward.h"
#include "mem/forward.h"

class MemBuf;
namespace Comm
{

/// switch to write-only mode.
/// Read will be monitored and any input will close
/// the connection.
void SetWriteOnly(const Comm::ConnectionPointer &);

/// switch out of write-only mode.
void StopWriteOnly(const Comm::ConnectionPointer &);

/**
 * Queue a write. callback is scheduled when the write
 * completes, on error, or on file descriptor close.
 *
 * free_func is used to free the passed buffer when the write has completed.
 */
void Write(const Comm::ConnectionPointer &conn, const char *buf, int size, AsyncCall::Pointer &callback, FREE *free_func);

/**
 * Queue a write. callback is scheduled when the write
 * completes, on error, or on file descriptor close.
 */
void Write(const Comm::ConnectionPointer &conn, MemBuf *mb, AsyncCall::Pointer &callback);

/// Cancel the write pending on FD. No action if none pending.
void WriteCancel(const Comm::ConnectionPointer &conn, const char *reason);

} // namespace Comm

#endif /* _SQUID_COMM_IOWRITE_H */

