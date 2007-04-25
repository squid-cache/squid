
/*
 * $Id: fde.cc,v 1.6 2007/04/25 11:30:18 adrian Exp $
 *
 * DEBUG: none          FDE
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
#include "fde.h"
#include "SquidTime.h"
#include "Store.h"
#include "comm.h"

bool
fde::readPending(int fdNumber)
{
    if (type == FD_SOCKET)
        return comm_has_pending_read(fdNumber);

    return read_handler ? true : false ;
}

void
fde::dumpStats (StoreEntry &dumpEntry, int fdNumber)
{
    if (!flags.open)
        return;

#ifdef _SQUID_MSWIN_

    storeAppendPrintf(&dumpEntry, "%4d 0x%-8lX %-6.6s %4d %7d%c %7d%c %-21s %s\n",
                      fdNumber,
                      win32.handle,
#else
    storeAppendPrintf(&dumpEntry, "%4d %-6.6s %4d %7d%c %7d%c %-21s %s\n",
                      fdNumber,
#endif
                      fdTypeStr[type],
                      timeout_handler ? (int) (timeout - squid_curtime) / 60 : 0,
                      bytes_read,
                      readPending(fdNumber) ? '*' : ' ',
                      bytes_written,
                      write_handler ? '*' : ' ',
                      remoteAddr(),
                      desc);
}

void
fde::DumpStats (StoreEntry *dumpEntry)
{
    int i;
    storeAppendPrintf(dumpEntry, "Active file descriptors:\n");
#ifdef _SQUID_MSWIN_

    storeAppendPrintf(dumpEntry, "%-4s %-10s %-6s %-4s %-7s* %-7s* %-21s %s\n",
                      "File",
                      "Handle",
#else
    storeAppendPrintf(dumpEntry, "%-4s %-6s %-4s %-7s* %-7s* %-21s %s\n",
                      "File",
#endif
                      "Type",
                      "Tout",
                      "Nread",
                      "Nwrite",
                      "Remote Address",
                      "Description");
#ifdef _SQUID_MSWIN_
    storeAppendPrintf(dumpEntry, "---- ---------- ------ ---- -------- -------- --------------------- ------------------------------\n");
#else
    storeAppendPrintf(dumpEntry, "---- ------ ---- -------- -------- --------------------- ------------------------------\n");
#endif

    for (i = 0; i < Squid_MaxFD; i++) {
        fd_table[i].dumpStats(*dumpEntry, i);
    }
}

char const *
fde::remoteAddr() const
{
    LOCAL_ARRAY(char, buf, 32);

    if (type != FD_SOCKET)
        return null_string;

    snprintf(buf, 32, "%s.%d", ipaddr, (int) remote_port);

    return buf;
}

void
fde::noteUse(PconnPool *pool)
{
    pconn.uses++;
    pconn.pool = pool;
}
