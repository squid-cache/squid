/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_COMPAT_OS_MINGW_H
#define SQUID_COMPAT_OS_MINGW_H

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

// needed for _commmit and _get_osfhandle
#if HAVE_IO_H
#include <io.h>
#endif

#if !HAVE_FSYNC
// _commit(fd) is API-compatible with fsync(fd) and has equivalent behaviour
inline int
fsync(int fd)
{
    return _commit(fd);
}
#endif

#endif /* _SQUID_MINGW_*/
#endif /* SQUID_COMPAT_OS_MINGW_H */
