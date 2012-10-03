/*
 * DEBUG: section 06    Disk I/O Routines
 * AUTHOR: Harvest Derived
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

#ifndef SQUID_DISK_H_
#define SQUID_DISK_H_

#include "typedefs.h"

class MemBuf;

// POD
class dread_ctrl
{
public:
    int fd;
    off_t offset;
    int req_len;
    char *buf;
    int end_of_file;
    DRCB *handler;
    void *client_data;
};

// POD
class dwrite_q
{
public:
    off_t file_offset;
    char *buf;
    size_t len;
    size_t buf_offset;
    dwrite_q *next;
    FREE *free_func;
};

int file_open(const char *path, int mode);
void file_close(int fd);

/* Adapter file_write for object callbacks */
template <class O>
void
FreeObject(void *address)
{
    O *anObject = static_cast <O *>(address);
    delete anObject;
}

void file_write(int, off_t, void const *, int len, DWCB *, void *, FREE *);
void file_write_mbuf(int fd, off_t, MemBuf mb, DWCB * handler, void *handler_data);
void file_read(int, char *, int, off_t, DRCB *, void *);
void disk_init(void);
void safeunlink(const char *path, int quiet);
int xrename(const char *from, const char *to); //disk.cc

#endif /* SQUID_DISK_H_ */
