/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef COMPAT_XPIPE_H
#define COMPAT_XPIPE_H

#if HAVE_UNISTD_H
#include <unistd.h>
#endif

#if _SQUID_WINDOWS_ || _SQUID_MINGW_

int xpipe(int fildes[2]);

#else /* _SQUID_WINDOWS_ || _SQUID_MINGW_ */

inline int
xpipe(int fildes[2])
{
    return pipe(fildes);
}

#endif /* _SQUID_WINDOWS_ || _SQUID_MINGW_ */

#endif /* COMPAT_XPIPE_H */