/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

// Author:  Jens-S. V?ckler <voeckler@rvs.uni-hannover.de>
//
// File:    convert.hh
//          Thu Oct 30 1997
//
// (c) 1997 Lehrgebiet Rechnernetze und Verteilte Systeme
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
// Revision 1.2  1999/01/19 11:00:50  voeckler
// added bool type workaround.
//
// Revision 1.1  1998/08/13 21:38:04  voeckler
// Initial revision
//
//
#ifndef _CONVERT_HH
#define _CONVERT_HH

#if !defined(__cplusplus)
#ifndef HAVE_BOOL
#define HAVE_BOOL 1
typedef char bool;
#define false 0
#define true  1
#endif
#endif /* __cplusplus */

#include <sys/types.h>
#include <sys/socket.h>

typedef char HostAddress[16]; // strlen("xxx.xxx.xxx.xxx\0") <= 16
typedef char SockAddress[24]; // strlen("xxx.xxx.xxx.xxx:xxxxx\0" ) < 24

const char*
my_inet_ntoa( const struct in_addr& a, HostAddress buffer );
  // purpose: thread-safely convert IPv4 address -> ASCII representation
  // paramtr: a (IN): networked representation of IPv4 address
  //          buffer (OUT): storage area to store representation into.
  // returns: pointer to buffer
  // goodies: INADDR_ANY will be converted to "*"

const char*
my_sock_ntoa( const struct sockaddr_in& a, SockAddress buffer );
  // purpose: thread-safely convert IPv4 socket pair into ASCII rep.
  // paramtr: a (IN): socket_in address 
  //          buffer (OUT): storage area to store representation into.
  // returns: pointer to buffer

const char*
my_sock_fd2a( int fd, SockAddress buffer, bool peer = true );
  // purpose: thread-safely convert IPv4 socket FD associated address
  //          to ASCII representation
  // paramtr: fd (IN): open socket FD
  //          buffer (OUT): storage area
  //          peer (IN): true, use peer (remote) socket pair
  //                     false, use own (local) socket pair
  // returns: NULL in case of error, or pointer to buffer otherwise
  //          Refer to errno in case of error (usually unconnected fd...)

int
convertHostname( const char* host, struct in_addr& dst );
  // purpose: convert a numeric or symbolic hostname
  // paramtr: host (IN): host description to convert
  //          dst (OUT): the internet address in network byteorder.
  // returns: -1 in case of error, see h_errno; 0 otherwise.

int
convertPortname( const char* port, unsigned short& dst );
  // purpose: convert a numeric or symbolic port number
  // paramtr: port (IN): port description to convert
  //          dst (OUT): port number in network byteorder.
  // returns: -1 in case of error, see errno; 0 otherwise.

#endif // _CONVERT_HH
