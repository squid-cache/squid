/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID__SRC_COMM_TCP_H
#define SQUID__SRC_COMM_TCP_H

namespace Comm
{

/// Configuration settings for the TCP keep-alive feature
class TcpKeepAlive
{
public:
    unsigned int idle = 0;
    unsigned int interval = 0;
    unsigned int timeout = 0;
    bool enabled = false;
};

/// apply configured TCP keep-alive settings to the given FD socket
void ApplyTcpKeepAlive(int fd, const TcpKeepAlive &);

} // namespace Comm

#endif /* SQUID__SRC_COMM_TCP_H */
