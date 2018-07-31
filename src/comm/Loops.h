/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef _SQUID_SRC_COMM_LOOPS_H
#define _SQUID_SRC_COMM_LOOPS_H

#include "comm/Flag.h"
#include "comm/forward.h"
#include "defines.h"

/* Comm layer select loops API.
 *
 * These API functions must be implemented by all FD IO loops used by Squid.
 * Defines are provided short-term for legacy code. These will disappear soon.
 */

namespace Comm
{

/// Initialize the module on Squid startup
void SelectLoopInit(void);

/// reset/undo/unregister the watch for an FD which was set by Comm::SetSelect()
inline void
ResetSelect(int fd)
{
    SetSelect(fd, COMM_SELECT_READ|COMM_SELECT_WRITE, nullptr, nullptr, 0);
}

/** Perform a select() or equivalent call.
 * This is used by the main select loop engine to check for FD with IO available.
 */
Comm::Flag DoSelect(int);

void QuickPollRequired(void);

/**
 * Max number of UDP messages to receive per call to the UDP receive poller.
 * This is a per-port limit for ICP/HTCP ports.
 * DNS has a separate limit.
 */
#if _SQUID_WINDOWS_
#define INCOMING_UDP_MAX 1
#else
#define INCOMING_UDP_MAX 15
#endif

/**
 * Max number of DNS messages to receive per call to DNS read handler
 */
#if _SQUID_WINDOWS_
#define INCOMING_DNS_MAX 1
#else
#define INCOMING_DNS_MAX 15
#endif

/**
 * Max number of new TCP connections to accept per call to the TCP listener poller.
 * This is a per-port limit for HTTP/HTTPS ports.
 */
#if _SQUID_WINDOWS_
#define INCOMING_TCP_MAX 1
#else
#define INCOMING_TCP_MAX 10
#endif
#define INCOMING_TOTAL_MAX (INCOMING_TCP_MAX+INCOMING_UDP_MAX+INCOMING_DNS_MAX)

} // namespace Comm

#endif /* _SQUID_SRC_COMM_LOOPS_H */

