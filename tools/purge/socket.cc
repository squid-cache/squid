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
// Linux glibc2 fixes for socket size parameters.
//
// Revision 1.2  1998/08/27 15:23:39  voeckler
// added TCP_NODELAY options at several places.
//
// Revision 1.1  1998/08/13 21:52:55  voeckler
// Initial revision
//

#include "squid.h"
#include "socket.hh"

#include <cerrno>
#include <cstring>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <unistd.h>

#include "convert.hh"

int
setSocketBuffers( int sockfd, int size )
// purpose: set socket buffers for both directions to the specified size
// paramtr: sockfd (IN): socket file descriptor
//          size (IN): new socket buffer size
// returns: -1 on setsockopt() errors, 0 otherwise
// warning: prints error message on stderr, errno will be changed
{
    if ( setsockopt( sockfd, SOL_SOCKET, SO_RCVBUF,
                     (char*) &size, sizeof(size) ) == -1 ) {
        perror( "setsockopt( SO_RCVBUF )" );
        return -1;
    }

    if ( setsockopt( sockfd, SOL_SOCKET, SO_SNDBUF,
                     (char*) &size, sizeof(size) ) == -1 ) {
        perror( "setsockopt( SO_SNDBUF )" );
        return -1;
    }

    return 0;
}

int
getSocketNoDelay( int sockfd )
// purpose: get state of the TCP_NODELAY of the socket
// paramtr: sockfd (IN): socket descriptor
// returns: 1, if TCP_NODELAY is set,
//          0, if TCP_NODELAY is not set,
//         -1, if an error occurred (e.g. datagram socket)
{
    int delay = 0;
    socklen_t len = sizeof(delay);
    if ( getsockopt( sockfd, IPPROTO_TCP, TCP_NODELAY,
                     (char*) &delay, &len ) == -1 ) {
        perror( "# getsockopt( TCP_NODELAY ) failed" );
        return -1;
    } else
        return ( delay ? 1 : 0 );
}

int
setSocketNoDelay( int sockfd, bool)
// purpose: get state of the TCP_NODELAY of the socket
// paramtr: sockfd (IN): socket descriptor
//          nodelay (IN): true, if TCP_NODELAY is to be set, false otherwise.
// returns: 0, if everything worked out o.k.
//         -1, if an error occurred (e.g. datagram socket)
{
    const int delay = 1;
    if ( setsockopt( sockfd, IPPROTO_TCP, TCP_NODELAY,
                     (const char*) &delay, sizeof(delay) ) == -1 ) {
        perror( "setsockopt( TCP_NODELAY ) failed" );
        return -1;
    } else
        return 0;
}

static int
commonCode(int &sockfd, bool nodelay, int sendBufferSize, int recvBufferSize)
// purpose: common code in server sockets and client sockets
// paramtr: sockfd (IO): socket filedescriptor
//          nodelay (IN): true=set TCP_NODELAY option.
//          sendBufferSize (IN): don't set (use sys defaults) if < 0
//          recvBufferSize (IN): don't set (use sys defaults) if < 0
// returns: 0 == if everything went ok, -1 otherwise
// warning: sockfd will be closed, if -1 is returned!
{
    // set TCP_NODELAY option, if that is wanted.
    // The socket API default is unset.
    if ( nodelay ) {
        const int delay = 1;
        if ( setsockopt( sockfd, IPPROTO_TCP, TCP_NODELAY,
                         (const char*) &delay, sizeof(delay) ) == -1 ) {
            perror( "setsockopt( TCP_NODELAY ) failed" );
            close(sockfd);
            return -1;
        }
    }

    // set the socket send buffer size explicitly, or use the system default
    if ( sendBufferSize >= 0 ) {
        if ( setsockopt( sockfd, SOL_SOCKET, SO_SNDBUF, (char*) &sendBufferSize,
                         sizeof(sendBufferSize) ) == -1 ) {
            perror( "setsockopt( SO_SNDBUF )" );
            close(sockfd);
            return -1;
        }
    }

    // set the socket recv buffer size explicitly, or use the system default
    if ( recvBufferSize >= 0 ) {
        if ( setsockopt( sockfd, SOL_SOCKET, SO_RCVBUF, (char*) &recvBufferSize,
                         sizeof(recvBufferSize) ) == -1 ) {
            perror( "setsockopt( SO_RCVBUF )" );
            close(sockfd);
            return -1;
        }
    }
    return 0;
}

int
connectTo( struct in_addr host, unsigned short port, bool nodelay,
           int sendBufferSize, int recvBufferSize )
// purpose: connect to a server as a client
// paramtr: host (IN): address describing the server
//          port (IN): port to connect at the server
//          nodelay (IN): true=set TCP_NODELAY option.
//          sendBufferSize (IN): don't set (use sys defaults) if < 0
//          recvBufferSize (IN): don't set (use sys defaults) if < 0
// returns: >=0 is the descriptor of the opened, connected socket,
//          -1  is an indication of an error (errno may have been reset).
{
    int sockfd = socket( PF_INET, SOCK_STREAM, IPPROTO_TCP );
    if ( sockfd == -1 ) {
        perror( "socket() failed" );
        return -1;
    }

    if ( commonCode( sockfd, nodelay, sendBufferSize, recvBufferSize ) == -1 )
        return -1;

    struct sockaddr_in server;
    memset( &server, 0, sizeof(server) );
    server.sin_family = AF_INET;
    server.sin_addr   = host;
    server.sin_port   = port;
    if ( connect( sockfd, (struct sockaddr*) &server, sizeof(server) ) == -1 ) {
        perror( "connect() failure" );
        close(sockfd);
        return -1;
    }

    return sockfd;
}

int
serverSocket( struct in_addr host, unsigned short port,
              int backlog, bool reuse, bool nodelay,
              int sendBufferSize, int recvBufferSize )
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
{
    int sockfd = socket( AF_INET, SOCK_STREAM, 0 );
    if ( sockfd == -1 ) {
        perror( "socket" );
        return -1;
    }

    if ( reuse ) {
        int opt = 1;
        if ( setsockopt( sockfd, SOL_SOCKET, SO_REUSEADDR,
                         (char*) &opt, sizeof(int) ) == -1) {
            perror( "setsockopt( SO_REUSEADDR )" );
            close( sockfd );
            return -1;
        }
    }

    if ( commonCode( sockfd, nodelay, sendBufferSize, recvBufferSize ) == -1 )
        return -1;

    struct sockaddr_in server;
    memset( &server, 0, sizeof(server) );
    server.sin_family = AF_INET;
    server.sin_port   = port;
    server.sin_addr   = host;
    if ( bind( sockfd, (SA*) &server, sizeof(server) ) == -1 ) {
        SockAddress socket;
        fprintf( stderr, "bind(%s): %s\n",
                 my_sock_ntoa(server,socket), strerror(errno) );
        close(sockfd);
        return -1;
    }

    if ( listen( sockfd, backlog ) == -1 ) {
        perror( "listen" );
        close(sockfd);
        return -1;
    }

    return sockfd;
}

