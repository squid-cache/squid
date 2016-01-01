/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef _SQUID_COMM_FORWARD_H
#define _SQUID_COMM_FORWARD_H

#include "base/RefCount.h"

#include <vector>

/// Abstraction layer for TCP, UDP, TLS, UDS and filedescriptor sockets.
namespace Comm
{

class Connection;
class ConnOpener;

typedef RefCount<Comm::Connection> ConnectionPointer;

typedef std::vector<Comm::ConnectionPointer> ConnectionList;

bool IsConnOpen(const Comm::ConnectionPointer &conn);

}; // namespace Comm

#endif /* _SQUID_COMM_FORWARD_H */

