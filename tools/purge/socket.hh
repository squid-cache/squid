/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

// Author:  Jens-S. V?ckler <voeckler@rvs.uni-hannover.de>
//
// File:    socket.hh
//          Sun May  3 1998
//
// (c) 1998 Lehrgebiet Rechnernetze und Verteilte Systeme
//          Universit?t Hannover, Germany
//
// Books:   W. Richard Steven, "Advanced Programming in the UNIX Environment",
//          Addison-Wesley, 1992.
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
// Revision 1.3  1999/01/19 11:00:50  voeckler
// added bool type workaround.
//
// Revision 1.2  1998/08/27 15:23:24  voeckler
// added TCP_NODELAY options at several places.
//
// Revision 1.1  1998/08/13 21:52:55  voeckler
// Initial revision
//
//
#ifndef _SOCKET_HH
#define _SOCKET_HH

#if !defined(__cplusplus)
#ifndef HAVE_BOOL
#define HAVE_BOOL
typedef int bool;
#define false 0
#define true  1
#endif
#endif /* __cplusplus */

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#if SOMAXCONN <= 5
#undef SOMAXCONN
#endif

#ifndef SOMAXCONN
#if defined(SOLARIS)
#if MAJOR < 5
#define SOMAXCONN 32
#else
#define SOMAXCONN 128
#endif
#elif defined(LINUX)
#define SOMAXCONN 128
#else
#define SOMAXCONN 5 // BSD
#endif // OS selection
#endif // !SOMAXCONN

#ifndef SA
#define SA struct sockaddr
#endif

int
setSocketBuffers( int fd, int size );
  // purpose: set socket buffers for both directions to the specified size
  // paramtr: size (IN): new socket buffer size
  // returns: -1 on setsockopt() errors, 0 otherwise
  // warning: prints error message on stderr, errno will be changed

int
getSocketNoDelay( int sockfd );
  // purpose: get state of the TCP_NODELAY of the socket
  // paramtr: sockfd (IN): socket descriptor
  // returns: 1, if TCP_NODELAY is set,
  //          0, if TCP_NODELAY is not set,
  //         -1, if an error occurred (e.g. datagram socket)


int
setSocketNoDelay( int sockfd, bool nodelay = true );
  // purpose: get state of the TCP_NODELAY of the socket
  // paramtr: sockfd (IN): socket descriptor
  //          nodelay (IN): true, if TCP_NODELAY is to be set, false otherwise.
  // returns: 0, if everything worked out o.k.
  //         -1, if an error occurred (e.g. datagram socket)

int
connectTo( struct in_addr host, unsigned short port, bool nodelay = false,
	   int sendBufferSize = -1, int recvBufferSize = -1 );
  // purpose: connect to a server as a client
  // paramtr: host (IN): address describing the server
  //          port (IN): port to connect at the server
  //          nodelay (IN): true=set TCP_NODELAY option.
  //          sendBufferSize (IN): don't set (use sys defaults) if < 0
  //          recvBufferSize (IN): don't set (use sys defaults) if < 0
  // returns: >=0 is the descriptor of the opened, connected socket,
  //          -1  is an indication of an error (errno may have been reset).

int
serverSocket( struct in_addr host, unsigned short port,
	      int backlog = SOMAXCONN, bool reuse = true, bool nodelay = false,
	      int sendBufferSize = -1, int recvBufferSize = -1 );
  // purpose: open a server socket for listening
  // paramtr: host (IN): host to bind locally to, use INADDRY_ANY for *
  //          port (IN): port to bind to, use 0 for system assigned
  //          backlog (IN): listen backlog queue length
  //          reuse (IN): set SO_REUSEADDR option - default usefully
  //          nodelay (IN): true=set TCP_NODELAY option.
  //            SETTING TCP_NODELAY ON A SERVER SOCKET DOES NOT MAKE SENSE!
  //          sendBufferSize (IN): don't set (use sys defaults) if < 0
  //          recvBufferSize (IN): don't set (use sys defaults) if < 0
  // returns: opened listening fd, or -1 on error.
  // warning: error message will be printed on stderr and errno reset.

#endif // _SOCKET_HH
