/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_COMPAT_PIPE_H
#define SQUID_COMPAT_PIPE_H

#if HAVE_UNISTD_H
#include <unistd.h>
#endif

#if _SQUID_WINDOWS_ || _SQUID_MINGW_

#if HAVE_WINDOWS_H
#include <windows.h>
#endif
#if HAVE_IO_H
#include <io.h>
#endif

inline int
pipe(int pipefd[2])
{
    return _pipe(pipefd, 4096, _O_BINARY);
}

#endif /* _SQUID_WINDOWS_ || _SQUID_MINGW_ */

#endif /* SQUID_COMPAT_PIPE_H */
