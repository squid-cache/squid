/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: none          FDE */

#include "squid.h"
#include "comm/Read.h"
#include "fd.h"
#include "fde.h"
#include "globals.h"
#include "SquidTime.h"
#include "Store.h"

fde *fde::Table = NULL;

bool
fde::readPending(int fdNumber)
{
    if (type == FD_SOCKET)
        return Comm::MonitorsRead(fdNumber);

    return read_handler ? true : false ;
}

void
fde::dumpStats (StoreEntry &dumpEntry, int fdNumber)
{
    if (!flags.open)
        return;

#if _SQUID_WINDOWS_

    storeAppendPrintf(&dumpEntry, "%4d 0x%-8lX %-6.6s %4d %7" PRId64 "%c %7" PRId64 "%c %-21s %s\n",
                      fdNumber,
                      win32.handle,
#else
    storeAppendPrintf(&dumpEntry, "%4d %-6.6s %4d %7" PRId64 "%c %7" PRId64 "%c %-21s %s\n",
                      fdNumber,
#endif
                      fdTypeStr[type],
                      timeoutHandler != NULL ? (int) (timeout - squid_curtime) : 0,
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
#if _SQUID_WINDOWS_

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
#if _SQUID_WINDOWS_
    storeAppendPrintf(dumpEntry, "---- ---------- ------ ---- -------- -------- --------------------- ------------------------------\n");
#else
    storeAppendPrintf(dumpEntry, "---- ------ ---- -------- -------- --------------------- ------------------------------\n");
#endif

    for (i = 0; i < Squid_MaxFD; ++i) {
        fd_table[i].dumpStats(*dumpEntry, i);
    }
}

char const *
fde::remoteAddr() const
{
    static char buf[MAX_IPSTRLEN+7]; // 7 = length of ':port' strings

    if (type != FD_SOCKET)
        return null_string;

    if ( *ipaddr )
        snprintf(buf, sizeof(buf), "%s:%u", ipaddr, remote_port);
    else
        local_addr.toUrl(buf, sizeof(buf)); // toHostStr does not include port.

    return buf;
}

void
fde::noteUse()
{
    ++ pconn.uses;
}

