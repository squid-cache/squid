/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* Inspired by previous work by Romeo Anghelache & Eric Stern. */

#ifndef SQUID_SRC_WIN32_H
#define SQUID_SRC_WIN32_H

#if _SQUID_WINDOWS_

void WIN32_ExceptionHandlerInit(void);

int Win32__WSAFDIsSet(int fd, fd_set* set);
DWORD WIN32_IpAddrChangeMonitorInit();

#endif

#endif /* SQUID_SRC_WIN32_H */

