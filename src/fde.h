
/*
 * $Id: fde.h,v 1.12 2006/09/15 20:40:29 serassio Exp $
 *
 *
 * SQUID Web Proxy Cache          http://www.squid-cache.org/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from
 *  the Internet community; see the CONTRIBUTORS file for full
 *  details.   Many organizations have provided support for Squid's
 *  development; see the SPONSORS file for full details.  Squid is
 *  Copyrighted (C) 2001 by the Regents of the University of
 *  California; see the COPYRIGHT file for full details.  Squid
 *  incorporates software developed and/or copyrighted by other
 *  sources; see the CREDITS file for full details.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *  
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *  
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111, USA.
 *
 */

#ifndef SQUID_FDE_H
#define SQUID_FDE_H
#include "comm.h"

class PconnPool;

class fde
{

public:
    /* NOTE: memset is used on fdes today. 20030715 RBC */
    static void DumpStats (StoreEntry *);

    char const *remoteAddr() const;
    void dumpStats (StoreEntry &, int);
    bool readPending(int);
    void noteUse(PconnPool *);

    unsigned int type;
    u_short local_port;
    u_short remote_port;

    struct IN_ADDR local_addr;
    unsigned char tos;
    char ipaddr[16];            /* dotted decimal address of peer */
    char desc[FD_DESC_SZ];

    struct
    {
	unsigned int open:1;
	unsigned int close_request:1;
	unsigned int write_daemon:1;
	unsigned int closing:1;
	unsigned int socket_eof:1;
	unsigned int nolinger:1;
	unsigned int nonblocking:1;
	unsigned int ipc:1;
	unsigned int called_connect:1;
	unsigned int nodelay:1;
	unsigned int close_on_exec:1;
	unsigned int read_pending:1;
	unsigned int write_pending:1;
    } flags;

    int bytes_read;
    int bytes_written;

    struct {
        int uses;                   /* ie # req's over persistent conn */
        PconnPool *pool;
    } pconn;

    unsigned epoll_state;

    struct _fde_disk disk;
    PF *read_handler;
    void *read_data;
    PF *write_handler;
    void *write_data;
    PF *timeout_handler;
    time_t timeout;
    void *timeout_data;
    void *lifetime_data;
    close_handler *closeHandler;        /* linked list */
    CommWriteStateData *wstate;         /* State data for comm_write */
    READ_HANDLER *read_method;
    WRITE_HANDLER *write_method;
#if USE_SSL
    SSL *ssl;
#endif
#ifdef _SQUID_MSWIN_
    struct { 
        long handle;
    } win32;
#endif

};

#endif /* SQUID_FDE_H */
