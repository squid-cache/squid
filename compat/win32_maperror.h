/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_COMPAT_WIN32_MAPERROR_H
#define SQUID_COMPAT_WIN32_MAPERROR_H

#if _SQUID_WINDOWS_ || _SQUID_MINGW_ && !_SQUID_CYGWIN_

/// maps a Windows system error code to a POSIX errno value
/// sets errno and _doserrno as side effects
void WIN32_maperror(unsigned long WIN32_oserrno);

#endif /* _SQUID_WINDOWS_ || _SQUID_MINGW_ && !_SQUID_CYGWIN_ */

#endif /* SQUID_COMPAT_WIN32_MAPERROR_H */