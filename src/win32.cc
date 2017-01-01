/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* Inspired by previous work by Romeo Anghelache & Eric Stern. */

#include "squid.h"

#if _SQUID_WINDOWS_

#include "fde.h"
#include "win32.h"

#include <csignal>
#if HAVE_WIN32_PSAPI
#include <psapi.h>
#endif
#if HAVE_MSWSOCK_H
#include <mswsock.h>
#endif

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
        raise(SIGBUS);
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

