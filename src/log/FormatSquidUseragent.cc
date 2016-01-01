/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 46    Access Log - Squid useragent format */

#include "squid.h"
#include "AccessLogEntry.h"
#include "HttpRequest.h"
#include "log/File.h"
#include "log/Formats.h"
#include "SquidTime.h"

void
Log::Format::SquidUserAgent(const AccessLogEntry::Pointer &al, Logfile * logfile)
{
    const char *agent = NULL;

    if (al->request)
        agent = al->request->header.getStr(Http::HdrType::USER_AGENT);

    if (!agent || *agent == '\0')
        agent = "-";

    char clientip[MAX_IPSTRLEN];
    al->getLogClientIp(clientip, MAX_IPSTRLEN);

    logfilePrintf(logfile, "%s [%s] \"%s\"\n",
                  clientip,
                  Time::FormatHttpd(squid_curtime),
                  agent);
}

