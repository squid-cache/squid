/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef _SQUID_SRC_COMM_FLAG_H
#define _SQUID_SRC_COMM_FLAG_H

namespace Comm
{

typedef enum {
    OK = 0,
    COMM_ERROR = -1,
    NOMESSAGE = -3,
    TIMEOUT = -4,
    SHUTDOWN = -5,
    IDLE = -6, /* there are no active fds and no pending callbacks. */
    INPROGRESS = -7,
    ERR_CONNECT = -8,
    ERR_DNS = -9,
    ERR_CLOSING = -10,
    ERR_PROTOCOL = -11, /* IPv4 or IPv6 cannot be used on the fd socket */
    ENDFILE = -12, /**< read(2) returned success, but with 0 bytes */
    ERR__END__ = -999999 /* Dummy entry to make syntax valid (comma on line above), do not use. New entries added above */
} Flag;

} // namespace Comm

#endif /* _SQUID_SRC_COMM_FLAG_H */

