/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "Debug.h"
#include "LogTags.h"

// old deprecated tag strings
const char * LogTags::Str_[] = {
    "TAG_NONE",
    "TCP_HIT",
    "TCP_MISS",
    "TCP_REFRESH_UNMODIFIED",
    "TCP_REFRESH_FAIL_OLD",
    "TCP_REFRESH_FAIL_ERR",
    "TCP_REFRESH_MODIFIED",
    "TCP_REFRESH",
    "TCP_CLIENT_REFRESH_MISS",
    "TCP_IMS_HIT",
    "TCP_INM_HIT",
    "TCP_SWAPFAIL_MISS",
    "TCP_NEGATIVE_HIT",
    "TCP_MEM_HIT",
    "TCP_DENIED",
    "TCP_DENIED_REPLY",
    "TCP_OFFLINE_HIT",
    "TCP_REDIRECT",
    "TCP_TUNNEL",
    "UDP_HIT",
    "UDP_MISS",
    "UDP_DENIED",
    "UDP_INVALID",
    "UDP_MISS_NOFETCH",
    "ICP_QUERY",
    "TYPE_MAX"
};

void
LogTags::update(const LogTags_ot t)
{
    assert(t < LOG_TYPE_MAX);
    debugs(83, 7, Str_[oldType] << " to " << Str_[t]);
    oldType = t;
}

/*
 * This method is documented in http://wiki.squid-cache.org/SquidFaq/SquidLogs#Squid_result_codes
 * Please keep the wiki up to date
 */
const char *
LogTags::c_str() const
{
    static char buf[1024];
    *buf = 0;
    int pos = 0;

    // source tags
    const int protoLen = 3;
    if (oldType && oldType < LOG_TYPE_MAX) {
        assert(Str_[oldType][protoLen] == '_');
        snprintf(buf, protoLen + 1, "%s", Str_[oldType]);
        pos += protoLen;
    }
    else
        pos += snprintf(buf, sizeof(buf), "NONE");

    if (collapsingHistory.collapsed())
        pos += snprintf(buf + pos, sizeof(buf) - pos, "_CF");

    const char *tag = Str_[oldType] + protoLen;
    pos += snprintf(buf + pos, sizeof(buf) - pos, "%s", tag);

    if (err.ignored)
        pos += snprintf(buf+pos,sizeof(buf)-pos, "_IGNORED");

    // error tags
    if (err.timedout)
        pos += snprintf(buf+pos,sizeof(buf)-pos, "_TIMEDOUT");
    if (err.aborted)
        pos += snprintf(buf+pos,sizeof(buf)-pos, "_ABORTED");

    return buf;
}

bool
LogTags::isTcpHit() const
{
    return
        (oldType == LOG_TCP_HIT) ||
        (oldType == LOG_TCP_IMS_HIT) ||
        (oldType == LOG_TCP_INM_HIT) ||
        (oldType == LOG_TCP_REFRESH_FAIL_OLD) ||
        (oldType == LOG_TCP_REFRESH_UNMODIFIED) ||
        (oldType == LOG_TCP_NEGATIVE_HIT) ||
        (oldType == LOG_TCP_MEM_HIT) ||
        (oldType == LOG_TCP_OFFLINE_HIT);
}

