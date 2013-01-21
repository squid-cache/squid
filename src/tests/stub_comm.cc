/*
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
#include "comm/Connection.h"
#include "comm/Loops.h"
#include "fde.h"

#define STUB_API "comm.cc"
#include "tests/STUB.h"

void comm_read(const Comm::ConnectionPointer &conn, char *buf, int size, IOCB *handler, void *handler_data) STUB
void comm_read(const Comm::ConnectionPointer &conn, char*, int, AsyncCall::Pointer &callback) STUB

/* should be in stub_CommRead */
#include "CommRead.h"
CommRead::CommRead(const Comm::ConnectionPointer &, char *, int, AsyncCall::Pointer &) STUB
CommRead::CommRead() STUB
DeferredReadManager::~DeferredReadManager() STUB
DeferredRead::DeferredRead(DeferrableRead *, void *, CommRead const &) STUB
void DeferredReadManager::delayRead(DeferredRead const &aRead) STUB
void DeferredReadManager::kickReads(int const count) STUB

void commSetCloseOnExec(int fd) STUB_NOP
int ignoreErrno(int ierrno) STUB_RETVAL(-1)

void commUnsetFdTimeout(int fd) STUB
int commSetNonBlocking(int fd) STUB_RETVAL(COMM_ERROR)
int commUnsetNonBlocking(int fd) STUB_RETVAL(-1)

// MinGW needs also a stub of _comm_close()
void _comm_close(int fd, char const *file, int line) STUB
int commSetTimeout(int fd, int timeout, AsyncCall::Pointer& callback) STUB_RETVAL(-1)
int comm_open_uds(int sock_type, int proto, struct sockaddr_un* addr, int flags) STUB_RETVAL(-1)
void comm_write(int fd, const char *buf, int size, AsyncCall::Pointer &callback, FREE * free_func) STUB
