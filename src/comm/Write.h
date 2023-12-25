/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
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

