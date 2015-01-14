/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 46    Access Log - Squid Custom format */

#include "squid.h"
#include "AccessLogEntry.h"
#include "format/Format.h"
#include "log/CustomLog.h"
#include "log/File.h"
#include "log/Formats.h"
#include "MemBuf.h"

void
Log::Format::SquidCustom(const AccessLogEntry::Pointer &al, CustomLog * log)
{
    static MemBuf mb;
    mb.reset();

    // XXX: because we do not yet have a neutral form of transaction slab. use AccessLogEntry
    log->logFormat->assemble(mb, al, log->logfile->sequence_number);

    logfilePrintf(log->logfile, "%s\n", mb.buf);
}

