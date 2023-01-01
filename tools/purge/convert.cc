/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

// Author:  Jens-S. V?ckler <voeckler@rvs.uni-hannover.de>
//
// File:    convert.cc
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
// Revision 1.3  2000/06/20 09:43:01  voeckler
// added FreeBSD related fixes and support.
//
// Revision 1.2  1999/01/19 11:00:50  voeckler
// Linux glibc2 fixes for sockets.
//
// Revision 1.1  1998/08/13 21:38:04  voeckler
// Initial revision
//

#include "squid.h"
#include "convert.hh"

#include <cstdlib>
#include <cstring>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#ifndef SA
#define SA struct sockaddr
#endif

const char*
my_inet_ntoa( const struct in_addr& a, HostAddress output )
// purpose: thread-safely convert IPv4 address -> ASCII representation
// paramtr: a (IN): networked representation of IPv4 address
//          buffer (OUT): storage area to store representation into.
// returns: pointer to buffer
// goodies: INADDR_ANY will be converted to "*"
{
    if ( a.s_addr == ntohl(INADDR_ANY) ) {
        // 'default' or '*' or ...
        output[0] = '*';
        output[1] = '\0';
    } else {
        // ANSI C++ forbids casting to an array type, nag, nag, nag...
        unsigned char s[sizeof(a.s_addr)];
        memcpy( s, &a.s_addr, sizeof(a.s_addr) );

        snprintf(output, sizeof(HostAddress), "%d.%d.%d.%d", s[0], s[1], s[2], s[3] );
    }
    return output;
}

const char*
my_sock_ntoa( const struct sockaddr_in& a, SockAddress buffer )
// purpose: thread-safely convert IPv4 socket pair into ASCII rep.
// paramtr: a (IN): sockaddr_in address
//          buffer (OUT): storage area to store representation into.
// returns: pointer to buffer
{
    HostAddress host;
    snprintf( buffer, sizeof(SockAddress), "%s:%u",
              my_inet_ntoa(a.sin_addr,host), ntohs(a.sin_port) );
    return buffer;
}

const char*
my_sock_fd2a( int fd, SockAddress buffer, bool peer )
// purpose: thread-safely convert IPv4 socket FD associated address
//          to ASCII representation
// paramtr: fd (IN): open socket FD
//          buffer (OUT): storage area
//          peer (IN): true, use peer (remote) socket pair
//                     false, use own (local) socket pair
// returns: NULL in case of error, or pointer to buffer otherwise
//          Refer to errno in case of error (usually unconnected fd...)
{
    struct sockaddr_in socket;
    socklen_t len = sizeof(socket);

    if ( (peer ? getpeername( fd, (SA*) &socket, &len ) :
            getsockname( fd, (SA*) &socket, &len )) == -1 )
        return NULL;
    else
        return my_sock_ntoa( socket, buffer );
}

int
convertHostname( const char* host, in_addr& dst )
// purpose: convert a numeric or symbolic hostname
// paramtr: host (IN): host description to convert
//          dst (OUT): the internet address in network byteorder.
// returns: -1 in case of error, see h_errno; 0 otherwise.
{
    if ( host == 0 ) return -1;
    unsigned long int h = inet_addr(host);
    if ( h == 0xFFFFFFFF && strncmp(host,"255.255.255.255",15) != 0 ) {
        // symbolic host
        struct hostent* dns = gethostbyname(host);
        if ( dns == NULL ) return -1;
        else memcpy( &dst.s_addr, dns->h_addr, dns->h_length );
    } else {
        // numeric host
        dst.s_addr = h;
    }
    return 0;
}

int
convertPortname( const char* port, unsigned short& dst )
// purpose: convert a numeric or symbolic port number
// paramtr: port (IN): port description to convert
//          dst (OUT): port number in network byteorder.
// returns: -1 in case of error, see errno; 0 otherwise.
{
    int p = strtoul(port,0,0);

    if ( p == 0 ) {
        // symbolic port
        struct servent* proto = getservbyname( port, "tcp" );
        if ( proto == NULL ) return -1;
        else dst = proto->s_port;
    } else {
        // numeric port
        dst = htons(p);
    }
    return 0;
}

