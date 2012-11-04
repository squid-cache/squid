/*
 * Windows support
 * AUTHOR: Guido Serassio <serassio@squid-cache.org>
 * inspired by previous work by Romeo Anghelache & Eric Stern.
 *
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

#include "squid.h"
#include "win32.h"

#if _SQUID_WINDOWS_
#if HAVE_WIN32_PSAPI
#include <psapi.h>
#endif
#ifndef _MSWSOCK_
#include <mswsock.h>
#endif
#include <fde.h>

SQUIDCEXTERN LPCRITICAL_SECTION dbg_mutex;
void WIN32_ExceptionHandlerCleanup(void);
static LPTOP_LEVEL_EXCEPTION_FILTER Win32_Old_ExceptionHandler = NULL;

int
Win32__WSAFDIsSet(int fd, fd_set FAR * set)
{
    fde *F = &fd_table[fd];
    SOCKET s = F->win32.handle;

    return __WSAFDIsSet(s, set);
}

LONG CALLBACK WIN32_ExceptionHandler(EXCEPTION_POINTERS* ep)
{
    EXCEPTION_RECORD* er;

    er = ep->ExceptionRecord;

    switch (er->ExceptionCode) {

    case EXCEPTION_ACCESS_VIOLATION:
        raise(SIGSEGV);
        break;

    case EXCEPTION_DATATYPE_MISALIGNMENT:

    case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:

    case EXCEPTION_IN_PAGE_ERROR:
        death(SIGBUS);
        break;

    default:
        break;
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

void WIN32_ExceptionHandlerInit()
{
#if !defined(_DEBUG)

    if (Win32_Old_ExceptionHandler == NULL)
        Win32_Old_ExceptionHandler = SetUnhandledExceptionFilter(WIN32_ExceptionHandler);

#endif
}

void WIN32_ExceptionHandlerCleanup()
{
    if (Win32_Old_ExceptionHandler != NULL)
        SetUnhandledExceptionFilter(Win32_Old_ExceptionHandler);
}

#endif /* SQUID_WINDOWS_ */
