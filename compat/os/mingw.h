/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_OS_MINGW_H
#define SQUID_OS_MINGW_H

#if _SQUID_MINGW_

/****************************************************************************
 *--------------------------------------------------------------------------*
 * DO *NOT* MAKE ANY CHANGES below here unless you know what you're doing...*
 *--------------------------------------------------------------------------*
 ****************************************************************************/

// include this header before winsock2.h
#if HAVE_WS2TCPIP_H
#include <ws2tcpip.h>
#endif

// error: #warning Please include winsock2.h before windows.h
#if HAVE_WINSOCK2_H
#include <winsock2.h>
#endif

// all windows native code requires windows.h
#if HAVE_WINDOWS_H
#include <windows.h>
#endif

#if defined(__GNUC__)
#if !defined(PRINTF_FORMAT_ARG1)
#define PRINTF_FORMAT_ARG1 __attribute__ ((format (gnu_printf, 1, 2)))
#endif
#if !defined(PRINTF_FORMAT_ARG2)
#define PRINTF_FORMAT_ARG2 __attribute__ ((format (gnu_printf, 2, 3)))
#endif
#if !defined(PRINTF_FORMAT_ARG3)
#define PRINTF_FORMAT_ARG3 __attribute__ ((format (gnu_printf, 3, 4)))
#endif
#endif /* __GNUC__ */

#endif /* _SQUID_MINGW_*/
#endif /* SQUID_OS_MINGW_H */
