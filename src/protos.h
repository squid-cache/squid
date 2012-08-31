/*
 * SQUID Web Proxy Cache          http://www.squid-cache.org/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from
 *  the Internet community; see the CONTRIBUTORS file for full
 *  details.   Many organizations have provided support for Squid's
 *  development; see the SPONSORS file for full details.  Squid is
 *  Copyrighted (C) 2001 by the Regents of the University of
 *  California; see the COPYRIGHT file for full details.  Squid
 *  incorporates software developed and/or copyrighted by other
 *  sources; see the CREDITS file for full details.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111, USA.
 *
 */
#ifndef SQUID_PROTOS_H
#define SQUID_PROTOS_H

/* for routines still in this file that take CacheManager parameters */
#include "ip/Address.h"
/* for parameters that still need these */
#include "enums.h"
/* some parameters stil need this */
#include "wordlist.h"
#include "anyp/ProtocolType.h"

#include "comm/forward.h"

extern void shut_down(int);
extern void rotate_logs(int);
extern void reconfigure(int);

#include "fatal.h"


        /* CygWin & Windows NT Port */
        /* win32.c */
#if _SQUID_WINDOWS_
        SQUIDCEXTERN int WIN32_Subsystem_Init(int *, char ***);
        SQUIDCEXTERN void WIN32_sendSignal(int);
        SQUIDCEXTERN void WIN32_Abort(int);
        SQUIDCEXTERN void WIN32_Exit(void);
        SQUIDCEXTERN void WIN32_SetServiceCommandLine(void);
        SQUIDCEXTERN void WIN32_InstallService(void);
        SQUIDCEXTERN void WIN32_RemoveService(void);
        SQUIDCEXTERN int SquidMain(int, char **);
#endif /* _SQUID_WINDOWS_ */
#if _SQUID_MSWIN_

        SQUIDCEXTERN int WIN32_pipe(int[2]);

            SQUIDCEXTERN int WIN32_getrusage(int, struct rusage *);
    SQUIDCEXTERN void WIN32_ExceptionHandlerInit(void);

    SQUIDCEXTERN int Win32__WSAFDIsSet(int fd, fd_set* set);
    SQUIDCEXTERN DWORD WIN32_IpAddrChangeMonitorInit();

#endif


#if USE_AUTH


    namespace Auth {
    /* call to ensure the auth component schemes exist. */
    extern void Init(void);
    } // namespace Auth

#endif /* USE_AUTH */

#endif /* SQUID_PROTOS_H */
