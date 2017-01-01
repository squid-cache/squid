/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 46    Access Log - Squid ICAP Logging */

#include "squid.h"

#if ICAP_CLIENT

#include "AccessLogEntry.h"
#include "format/Quoting.h"
#include "fqdncache.h"
#include "HttpRequest.h"
#include "log/File.h"
#include "log/Formats.h"
#include "SquidConfig.h"
#include "SquidTime.h"

void
Log::Format::SquidIcap(const AccessLogEntry::Pointer &al, Logfile * logfile)
{
    const char *client = NULL;
    const char *user = NULL;
    char tmp[MAX_IPSTRLEN], clientbuf[MAX_IPSTRLEN];

    if (al->cache.caddr.isAnyAddr()) { // ICAP OPTIONS xactions lack client
        client = "-";
    } else {
        if (Config.onoff.log_fqdn)
            client = fqdncache_gethostbyaddr(al->cache.caddr, FQDN_LOOKUP_IF_MISS);
        if (!client)
            client = al->cache.caddr.toStr(clientbuf, MAX_IPSTRLEN);
    }

#if USE_AUTH
    if (al->request != NULL && al->request->auth_user_request != NULL)
        user = ::Format::QuoteUrlEncodeUsername(al->request->auth_user_request->username());
#endif

    if (!user)
        user = ::Format::QuoteUrlEncodeUsername(al->cache.extuser);

#if USE_OPENSSL
    if (!user)
        user = ::Format::QuoteUrlEncodeUsername(al->cache.ssluser);
#endif

    if (!user)
        user = ::Format::QuoteUrlEncodeUsername(al->cache.rfc931);

    if (user && !*user)
        safe_free(user);

    logfilePrintf(logfile, "%9ld.%03d %6d %s %s/%03d %" PRId64 " %s %s %s -/%s -\n",
                  (long int) current_time.tv_sec,
                  (int) current_time.tv_usec / 1000,
                  al->icap.trTime,
                  client,
                  al->icap.outcome,
                  al->icap.resStatus,
                  al->icap.bytesRead,
                  Adaptation::Icap::ICAP::methodStr(al->icap.reqMethod),
                  al->icap.reqUri.termedBuf(),
                  user ? user : "-",
                  al->icap.hostAddr.toStr(tmp, MAX_IPSTRLEN));
    safe_free(user);
}
#endif

