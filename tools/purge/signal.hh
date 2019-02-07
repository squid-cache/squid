/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

// Author:   Jens-S. V?ckler <voeckler@rvs.uni-hannover.de>
// File:     signal.hh
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
// Revision 1.4  2000/09/21 10:59:27  cached
// introduced extern "C" to function pointer type.
//
// Revision 1.3  1999/01/19 11:53:49  voeckler
// added bool compatibility definitions.
//
// Revision 1.2  1999/01/19 11:00:50  voeckler
// added psignal(int,const char*) compatibility function declaration.
//
// Revision 1.1  1998/08/13 21:51:58  voeckler
// Initial revision
//
//

#ifndef _SIGNAL_HH
#define _SIGNAL_HH

#include "squid.h"

#include <csignal>

#if !defined(__cplusplus)
#ifndef HAVE_BOOL
#define HAVE_BOOL
typedef int bool;
#define false 0
#define true  1
#endif
#endif /* __cplusplus */

#if 1 // so far, all systems I know use void
# define SIGRETTYPE void
#else
# define SIGRETTYPE int
#endif

#if defined(SUNOS) && defined(SUN)
# define SIGPARAM void
#else // SOLARIS, LINUX, IRIX, AIX, SINIXY
# define SIGPARAM int
#endif

extern "C" {
  typedef SIGRETTYPE SigFunc( SIGPARAM );
}

SigFunc*
Signal( int signo, SigFunc* newhandler, bool doInterrupt );
  // purpose: install reliable signals
  // paramtr: signo (IN): signal for which a handler is to be installed
  //          newhandler (IN): function pointer to the signal handler
  //          doInterrupt (IN): interrupted system calls wanted!
  // returns: the old signal handler, or SIG_ERR in case of error.

SIGRETTYPE
sigChild( int signo );
  // purpose: supply ad hoc child handler with output on stderr
  // paramtr: signo (IN): == SIGCHLD
  // returns: only if OS uses a return type for signal handler

#endif // _SIGNAL_HH
