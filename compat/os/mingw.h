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

// all windows native code requires windows.h
#if HAVE_WINDOWS_H
#include <windows.h>
#endif

#endif /* _SQUID_MINGW_*/
#endif /* SQUID_OS_MINGW_H */
