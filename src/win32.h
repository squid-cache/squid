/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* Inspired by previous work by Romeo Anghelache & Eric Stern. */

#ifndef SQUID_WIN32_H_
#define SQUID_WIN32_H_

#if _SQUID_WINDOWS_

void WIN32_ExceptionHandlerInit(void);

int Win32__WSAFDIsSet(int fd, fd_set* set);
DWORD WIN32_IpAddrChangeMonitorInit();

#endif

#endif /* SQUID_WIN32_H_ */

