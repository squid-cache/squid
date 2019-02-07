/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

// Author:   Jens-S. V?ckler <voeckler@rvs.uni-hannover.de>
// File:     signal.cc
// Date:     Sat Feb 28 1998
// Compiler: gcc 2.7.2.x series
//
// Books:    W. Richard Steven, "Advanced Programming in the UNIX Environment",
//           Addison-Wesley, 1992.
//
// (c) 1998 Lehrgebiet Rechnernetze und Verteilte Systeme
//          Universit?t Hannover, Germany
//
// Permission to use, copy, modify, distribute, and sell this software
// and its documentation for any purpose is hereby granted without fee,
// provided that (i) the above copyright notices and this permission
// notice appear in all copies of the software and related documentation,
// and (ii) the names of the Lehrgebiet Rechnernetze und Verteilte
// Systeme and the University of Hannover may not be used in any
// advertising or publicity relating to the software without the
// specific, prior written permission of Lehrgebiet Rechnernetze und
// Verteilte Systeme and the University of Hannover.
//
// THE SOFTWARE IS PROVIDED "AS-IS" AND WITHOUT WARRANTY OF ANY KIND,
// EXPRESS, IMPLIED OR OTHERWISE, INCLUDING WITHOUT LIMITATION, ANY
// WARRANTY OF MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE.
//
// IN NO EVENT SHALL THE LEHRGEBIET RECHNERNETZE UND VERTEILTE SYSTEME OR
// THE UNIVERSITY OF HANNOVER BE LIABLE FOR ANY SPECIAL, INCIDENTAL,
// INDIRECT OR CONSEQUENTIAL DAMAGES OF ANY KIND, OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER OR NOT
// ADVISED OF THE POSSIBILITY OF DAMAGE, AND ON ANY THEORY OF LIABILITY,
// ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
// SOFTWARE.
//
// Revision 1.3  1999/01/19 13:11:52  cached
// adaptations necessary for AIX.
//
// Revision 1.2  1999/01/19 11:00:50  voeckler
// added psignal(int,const char*) compatibility function.
//
// Revision 1.1  1998/08/13 21:51:58  voeckler
// Initial revision
//

#include "squid.h"
#include "signal.hh"

#include <cerrno>
#include <cstring>
#include <memory.h>
#include <unistd.h>
#include <sys/wait.h>

SigFunc*
Signal( int signo, SigFunc* newhandler, bool doInterrupt )
// purpose: install reliable signals
// paramtr: signo (IN): signal for which a handler is to be installed
//          newhandler (IN): function pointer to the signal handler
//          doInterrupt (IN): interrupted system calls wanted!
// returns: the old signal handler, or SIG_ERR in case of error.
{
    struct sigaction action, old;

    memset( &old, 0, sizeof(old) );
    memset( &action, 0, sizeof(action) );

    // action.sa_handler = newhandler; I HATE TYPE-OVERCORRECTNESS !
    memmove( &action.sa_handler, &newhandler, sizeof(SigFunc*) );
    sigemptyset( &action.sa_mask );

    if ( signo == SIGCHLD ) {
        action.sa_flags |= SA_NOCLDSTOP;

#ifdef SA_NODEFER
        action.sa_flags |= SA_NODEFER;   // SYSV: don't block current signal
#endif
    }

    if ( signo == SIGALRM || doInterrupt ) {
#ifdef SA_INTERRUPT
        action.sa_flags |= SA_INTERRUPT; // SunOS, obsoleted by POSIX
#endif
    } else {
#ifdef SA_RESTART
        action.sa_flags |= SA_RESTART;   // BSD, SVR4
#endif
    }

    return ( sigaction( signo, &action, &old ) < 0 ) ?
           (SigFunc*) SIG_ERR :
           (SigFunc*) old.sa_handler;
}

SIGRETTYPE
sigChild( int signo )
// purpose: supply ad hoc child handler with output on stderr
// paramtr: signo (IN): == SIGCHLD
// returns: only if OS uses a return type for signal handler
// seealso: Stevens, UNP, figure 5.11 *and* Stevens, APUE, figure 8.3
{
    pid_t pid;
    int  status = signo; // to stop GNU from complaining...

    int saveerr = errno;
    while ( (pid = waitpid( -1, &status, WNOHANG )) > 0 ) {
        if ( WIFEXITED(status) ) {
            fprintf( stderr, "child (pid=%ld) reaped, status %d\n%c",
                     (long) pid, WEXITSTATUS(status), 0 );
        } else if ( WIFSIGNALED(status) ) {
            fprintf( stderr, "child (pid=%ld) died on signal %d%s\n%c",
                     (long) pid, WTERMSIG(status),
#ifdef WCOREDUMP
                     WCOREDUMP(status) ? " (core generated)" : "",
#else
                     "",
#endif
                     0 );
        } else {
            fprintf( stderr, "detected dead child (pid=%ld), status %d\n%c",
                     (long) pid, status, 0 );
        }
    }
    errno = saveerr;

#if SIGRETTYPE != void
    return 0;
#endif
}

