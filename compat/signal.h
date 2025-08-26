/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_COMPAT_SIGNAL_H
#define SQUID_COMPAT_SIGNAL_H

#if !defined(SIGHUP)
#define SIGHUP  1   /* hangup */
#endif
#if !defined(SIGKILL)
#define SIGKILL 9   /* kill (cannot be caught or ignored) */
#endif
#if !defined(SIGBUS)
#define SIGBUS  10  /* bus error */
#endif
#if !defined(SIGPIPE)
#define SIGPIPE 13  /* write on a pipe with no one to read it */
#endif
#if !defined(SIGALRM)
#define SIGALRM 14  /* real-time timer expired */
#endif
#if !defined(SIGCHLD)
#define SIGCHLD 20  /* to parent on child stop or exit */
#endif
#if !defined(SIGUSR1)
#define SIGUSR1 30  /* user defined signal 1 */
#endif
#if !defined(SIGUSR2)
#define SIGUSR2 31  /* user defined signal 2 */
#endif

/// POSIX kill(2) equivalent
int xkill(pid_t pid, int sig);

/// true if pid can be sent a signal (no signal is sent)
inline bool
IsPidValid(pid_t pid);

#if !defined(WIFEXITED)
inline int
WIFEXITED(int status) {
    return (status & 0x7f) == 0;
}
#endif

#if !defined(WEXITSTATUS)
inline int
WEXITSTATUS(int status) {
    return (status & 0xff00) >> 8;
}
#endif

#if !defined(WIFSIGNALED)
inline int
WIFSIGNALED(int status) {
    return (status & 0x7f) != 0;
}
#endif

#if !defined(WTERMSIG)
inline int
WTERMSIG(int status) {
    return (status & 0x7f);
}
#endif

#if !(_SQUID_WINDOWS_ || _SQUID_MINGW_)

inline int xkill(pid_t pid, int sig)
{
    return kill(pid, sig);
}

inline bool
IsPidValid(pid_t pid)
{
    return kill(pid, 0) == 0;
}

#endif /* !(_SQUID_WINDOWS_ || _SQUID_MINGW_) */

#endif /* SQUID_COMPAT_SIGNAL_H */