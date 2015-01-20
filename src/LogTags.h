/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_LOGTAGS_H
#define SQUID_SRC_LOGTAGS_H

/** Squid transaction result code/tag set.
 *
 * These codes indicate how the request was received
 * and some details about its processing pathway.
 *
 * see also http://wiki.squid-cache.org/SquidFaq/SquidLogs#Squid_result_codes
 * for details on particular components.
 */
typedef enum {
    LOG_TAG_NONE = 0,
    LOG_TCP_HIT,
    LOG_TCP_MISS,
    LOG_TCP_REFRESH_UNMODIFIED, // refresh from origin revalidated existing entry
    LOG_TCP_REFRESH_FAIL_OLD,   // refresh from origin failed, stale reply sent
    LOG_TCP_REFRESH_FAIL_ERR,   // refresh from origin failed, error forwarded
    LOG_TCP_REFRESH_MODIFIED,   // refresh from origin replaced existing entry
    LOG_TCP_CLIENT_REFRESH_MISS,
    LOG_TCP_IMS_HIT,
    LOG_TCP_SWAPFAIL_MISS,
    LOG_TCP_NEGATIVE_HIT,
    LOG_TCP_MEM_HIT,
    LOG_TCP_DENIED,
    LOG_TCP_DENIED_REPLY,
    LOG_TCP_OFFLINE_HIT,
    LOG_TCP_REDIRECT,
    LOG_TCP_TUNNEL,             // a binary tunnel was established for this transaction
    LOG_UDP_HIT,
    LOG_UDP_MISS,
    LOG_UDP_DENIED,
    LOG_UDP_INVALID,
    LOG_UDP_MISS_NOFETCH,
    LOG_ICP_QUERY,
    LOG_TYPE_MAX
} LogTags;

/// list of string representations for LogTags
extern const char *LogTags_str[];

/// determine if the log tag code indicates a cache HIT
inline bool logTypeIsATcpHit(LogTags code)
{
    return
        (code == LOG_TCP_HIT) ||
        (code == LOG_TCP_IMS_HIT) ||
        (code == LOG_TCP_REFRESH_FAIL_OLD) ||
        (code == LOG_TCP_REFRESH_UNMODIFIED) ||
        (code == LOG_TCP_NEGATIVE_HIT) ||
        (code == LOG_TCP_MEM_HIT) ||
        (code == LOG_TCP_OFFLINE_HIT);
}

/// iterator for LogTags enumeration
inline LogTags &operator++ (LogTags &aLogType)
{
    int tmp = (int)aLogType;
    aLogType = (LogTags)(++tmp);
    return aLogType;
}

#endif

