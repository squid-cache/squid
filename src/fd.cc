
/*
 * $Id: fd.cc,v 1.18 1998/02/02 21:15:01 wessels Exp $
 *
 * DEBUG: section 51    Filedescriptor Functions
 * AUTHOR: Duane Wessels
 *
 * SQUID Internet Object Cache  http://squid.nlanr.net/Squid/
 * --------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from the
 *  Internet community.  Development is led by Duane Wessels of the
 *  National Laboratory for Applied Network Research and funded by
 *  the National Science Foundation.
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
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *  
 */

#include "squid.h"

static void fdUpdateBiggest(int fd, unsigned int status);

static void
fdUpdateBiggest(int fd, unsigned int status)
{
    if (fd < Biggest_FD)
	return;
    assert(fd < Squid_MaxFD);
    if (fd > Biggest_FD) {
	if (status != FD_OPEN)
	    debug(51,1) ("fdUpdateBiggest: status != FD_OPEN\n");
	Biggest_FD = fd;
	return;
    }
    /* if we are here, then fd == Biggest_FD */
    if (status != FD_CLOSE)
	debug(51,1) ("fdUpdateBiggest: status != FD_CLOSE\n");
    while (fd_table[Biggest_FD].open != FD_OPEN)
	Biggest_FD--;
}

void
fd_close(int fd)
{
    fde *F = &fd_table[fd];
    if (F->type == FD_FILE) {
	assert(F->read_handler == NULL);
	assert(F->write_handler == NULL);
    }
    fdUpdateBiggest(fd, F->open = FD_CLOSE);
    Number_FD--;
    memset(F, '\0', sizeof(fde));
    F->timeout = 0;
}

void
fd_open(int fd, unsigned int type, const char *desc)
{
    fde *F = &fd_table[fd];
    assert(fd >= 0);
    if(F->open != 0) {
	debug(51, 1) ("WARNING: Closing open FD %4d\n", fd);
	fd_close(fd);
    }
    assert(F->open == 0);
    debug(51, 3) ("fd_open FD %d %s\n", fd, desc);
    F->type = type;
    fdUpdateBiggest(fd, F->open = FD_OPEN);
    if (desc)
	xstrncpy(F->desc, desc, FD_DESC_SZ);
    Number_FD++;
}

void
fd_note(int fd, const char *s)
{
    fde *F = &fd_table[fd];
    xstrncpy(F->desc, s, FD_DESC_SZ);
}

void
fd_bytes(int fd, int len, unsigned int type)
{
    fde *F = &fd_table[fd];
    if (len < 0)
	return;
    assert(type == FD_READ || type == FD_WRITE);
    if (type == FD_READ)
	F->bytes_read += len;
    else
	F->bytes_written += len;
}

void
fdFreeMemory(void)
{
    safe_free(fd_table);
}

void
fdDumpOpen(void)
{
    int i;
    fde *F;
    for (i = 0; i < Squid_MaxFD; i++) {
	F = &fd_table[i];
	if (!F->open)
	    continue;
	if (i == fileno(debug_log))
	    continue;
	debug(51, 1) ("Open FD %4d %s\n", i, F->desc);
    }
}
