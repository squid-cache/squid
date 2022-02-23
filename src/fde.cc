/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 05    Comm */

#include "squid.h"
#include "comm/Read.h"
#include "Debug.h"
#include "fd.h"
#include "fde.h"
#include "globals.h"
#include "SquidTime.h"
#include "Store.h"

fde *fde::Table = nullptr;

void
fde::setIo(READ_HANDLER *reader, WRITE_HANDLER *writer)
{
    assert(reader);
    assert(writer);
    assert(!flags.read_pending); // this method is only meant for new FDs

    readMethod_ = reader;
    writeMethod_ = writer;
}

void
fde::useDefaultIo()
{
    debugs(5, 7, "old read_pending=" << flags.read_pending);

    // Some buffering readers are using external-to-them buffers (e.g., inBuf)
    // and might leave true flags.read_pending behind without losing data. We
    // must clear the flag here because default I/O methods do not know about it
    // and will leave it set forever, resulting in I/O loops.
    flags.read_pending = false;

    readMethod_ = default_read_method;
    writeMethod_ = default_write_method;
}

/// use I/O methods that maintain an internal-to-them buffer
void
fde::useBufferedIo(READ_HANDLER *bufferingReader, WRITE_HANDLER *bufferingWriter)
{
    debugs(5, 7, "read_pending=" << flags.read_pending);

    assert(bufferingReader);
    assert(bufferingWriter);
    // flags.read_pending ought to be false here, but these buffering methods
    // can handle a stale true flag so we do not check or reset it

    readMethod_ = bufferingReader;
    writeMethod_ = bufferingWriter;
}

bool
fde::readPending(int fdNumber) const
{
    if (type == FD_SOCKET)
        return Comm::MonitorsRead(fdNumber);

    return read_handler != nullptr;
}

void
fde::dumpStats(StoreEntry &dumpEntry, int fdNumber) const
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
                      timeoutHandler ? (int) (timeout - squid_curtime) : 0,
                      bytes_read,
                      readPending(fdNumber) ? '*' : ' ',
                      bytes_written,
                      write_handler ? '*' : ' ',
                      remoteAddr(),
                      desc);
}

void
fde::DumpStats(StoreEntry *dumpEntry)
{
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

    for (int i = 0; i < Squid_MaxFD; ++i) {
        fde::Table[i].dumpStats(*dumpEntry, i);
    }
}

char const *
fde::remoteAddr() const
{
    static char buf[MAX_IPSTRLEN+7]; // 7 = length of ':port' strings
    *buf = 0;

    if (type == FD_SOCKET) {
        if (*ipaddr)
            snprintf(buf, sizeof(buf), "%s:%u", ipaddr, remote_port);
        else
            local_addr.toUrl(buf, sizeof(buf)); // toHostStr does not include port.
    }

    return buf;
}

void
fde::Init()
{
    assert(!Table);
    Table = static_cast<fde *>(xcalloc(Squid_MaxFD, sizeof(fde)));
}

