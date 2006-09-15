/*
 * $Id: stub_comm.cc,v 1.5 2006/09/14 20:13:23 serassio Exp $
 *
 * DEBUG: section 84    Helper process maintenance
 * AUTHOR: Robert Collins
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

#include "squid.h"
#include "comm.h"
#include "CommRead.h"
#include "fde.h"

DeferredReadManager::~DeferredReadManager()
{
    /* no networked tests yet */
}

DeferredRead::DeferredRead (DeferrableRead *, void *, CommRead const &)
{
    fatal ("Not implemented");
}

void
DeferredReadManager::delayRead(DeferredRead const &aRead)
{
    fatal ("Not implemented");
}

void
DeferredReadManager::kickReads(int const count)
{
    fatal ("Not implemented");
}

void
comm_read(int fd, char *buf, int size, IOCB *handler, void *handler_data)
{
    fatal ("Not implemented");
}

/* should be in stub_CommRead */
#include "CommRead.h"
CommRead::CommRead (int fd, char *buf, int len, IOCB *handler, void *data)
{
    fatal ("Not implemented");
}

CommRead::CommRead ()
{
    fatal ("Not implemented");
}

void
commSetCloseOnExec(int fd)
{
    /* for tests... ignore */
}

void
commSetSelect(int fd, unsigned int type, PF * handler, void *client_data,
              time_t timeout)
{
    /* all test code runs synchronously at the moment */
}

int
ignoreErrno(int ierrno)
{
    fatal ("Not implemented");
    return -1;
}

int
commSetTimeout(int fd, int timeout, PF * handler, void *data)
{
    fatal ("Not implemented");
    return -1;
}

int
commUnsetNonBlocking(int fd)
{
    fatal ("Not implemented");
    return -1;
}

/* bah, cheating on stub count */

pid_t
ipcCreate(int type, const char *prog, const char *const args[], const char *name, int *rfd, int *wfd, void **hIpc)
{
    fatal ("Not implemented");
    return -1;
}

void
comm_init(void)
{
    fd_table =(fde *) xcalloc(Squid_MaxFD, sizeof(fde));

    /* Keep a few file descriptors free so that we don't run out of FD's
     * after accepting a client but before it opens a socket or a file.
     * Since Squid_MaxFD can be as high as several thousand, don't waste them */
    RESERVED_FD = XMIN(100, Squid_MaxFD / 4);
}

/* MinGW needs also a stub of _comm_close() */
void
_comm_close(int fd, char const *file, int line)
{
    fatal ("Not implemented");
}
