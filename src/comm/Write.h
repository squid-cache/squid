#ifndef _SQUID_COMM_IOWRITE_H
#define _SQUID_COMM_IOWRITE_H

#include "base/AsyncCall.h"

namespace Comm
{

/**
 * Queue a write. callback is scheduled when the write
 * completes, on error, or on file descriptor close.
 *
 * free_func is used to free the passed buffer when the write has completed.
 */
void Write(int fd, const char *buf, int size, AsyncCall::Pointer &callback, FREE *free_func);

/**
 * Queue a write. callback is scheduled when the write
 * completes, on error, or on file descriptor close.
 */
void Write(int fd, MemBuf *mb, AsyncCall::Pointer &callback);

/// Cancel the write pending on FD. No action if none pending.
void WriteCancel(int fd, const char *reason);

// callback handler to process an FD which is available for writing.
extern PF HandleWrite;

}; // namespace Comm

#endif /* _SQUID_COMM_IOWRITE_H */
