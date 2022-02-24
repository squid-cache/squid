/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 46    Access Log - Squid referer format */

#include "squid.h"
#include "AccessLogEntry.h"
#include "HttpRequest.h"
#include "log/File.h"
#include "log/Formats.h"
#include "SquidTime.h"

void
Log::Format::SquidReferer(const AccessLogEntry::Pointer &al, Logfile *logfile)
{
    const char *referer = NULL;
    if (al->request)
        referer = al->request->header.getStr(Http::HdrType::REFERER);

    if (!referer || *referer == '\0')
        referer = "-";

    char clientip[MAX_IPSTRLEN];
    al->getLogClientIp(clientip, MAX_IPSTRLEN);

    const SBuf url = !al->url.isEmpty() ? al->url : ::Format::Dash;

    logfilePrintf(logfile, "%9ld.%03d %s %s " SQUIDSBUFPH "\n",
                  (long int) current_time.tv_sec,
                  (int) current_time.tv_usec / 1000,
                  clientip,
                  referer,
                  SQUIDSBUFPRINT(url));
}

