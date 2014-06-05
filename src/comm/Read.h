#ifndef _SQUID_COMM_READ_H
#define _SQUID_COMM_READ_H

#include "base/AsyncCall.h"
#include "CommCalls.h"
#include "comm/forward.h"

class SBuf;

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
 * The returned flag is also placed in params.flag.
 *
 * \retval COMM_OK          data has been read and placed in buf, amount in params.size
 * \retval COMM_ERROR       an error occured, the code is placed in params.xerrno
 * \retval COMM_INPROGRESS  unable to read at this time, or a minor error occured
 * \retval COMM_ERR_CLOSING 0-byte read has occured.
 *                          Usually indicates the remote end has disconnected.
 */
comm_err_t ReadNow(CommIoCbParams &params, SBuf &buf);

/// Cancel the read pending on FD. No action if none pending.
void ReadCancel(int fd, AsyncCall::Pointer &callback);

/// callback handler to process an FD which is available for reading
extern PF HandleRead;

} // namespace Comm

// Legacy API to be removed
void comm_read_base(const Comm::ConnectionPointer &conn, char *buf, int len, AsyncCall::Pointer &callback);
inline void comm_read(const Comm::ConnectionPointer &conn, char *buf, int len, AsyncCall::Pointer &callback)
{
    assert(buf != NULL);
    comm_read_base(conn, buf, len, callback);
}
void comm_read_cancel(int fd, IOCB *callback, void *data);
inline void comm_read_cancel(int fd, AsyncCall::Pointer &callback) {Comm::ReadCancel(fd,callback);}

#endif /* _SQUID_COMM_READ_H */
