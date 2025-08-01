/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_COMPAT_SIGNAL_H
#define SQUID_COMPAT_SIGNAL_H

#if !defined(SIGKILL)
#define SIGHUP  1   /* hangup */
#define SIGKILL 9   /* kill (cannot be caught or ignored) */
#define SIGBUS  10  /* bus error */
#define SIGPIPE 13  /* write on a pipe with no one to read it */
#define SIGCHLD 20  /* to parent on child stop or exit */
#define SIGUSR1 30  /* user defined signal 1 */
#define SIGUSR2 31  /* user defined signal 2 */
#endif

/// POSIX kill(2) equivalent
int xkill(pid_t pid, int sig);

#if !(_SQUID_WINDOWS_ || _SQUID_MINGW_)

inline int xkill(pid_t pid, int sig)
{
    return kill(pid, sig);
}

#endif /* !(_SQUID_WINDOWS_ || _SQUID_MINGW_) */
#endif /* SQUID_COMPAT_SIGNAL_H */