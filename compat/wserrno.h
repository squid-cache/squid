/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_COMPAT_WSERRNO_H
#define SQUID_COMPAT_WSERRNO_H

#if _SQUID_WINDOWS_ || _SQUID_MINGW_

/**
 * Squid socket code is written to handle POSIX errno codes.
 * Set errno to the relevant POSIX or WSA code.
 */
void SetErrnoFromWsaError();

#endif

#endif /* SQUID_COMPAT_WSERRNO_H */
