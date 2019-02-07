/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
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
    LOG_TCP_REFRESH,            // refresh from origin started, but still pending
    LOG_TCP_CLIENT_REFRESH_MISS,
    LOG_TCP_IMS_HIT,
    LOG_TCP_INM_HIT,
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
} LogTags_ot;

class LogTags
{
public:
    LogTags(LogTags_ot t) : oldType(t) {assert(oldType < LOG_TYPE_MAX);}
    // XXX: this operator does not reset flags
    // TODO: either replace with a category-only setter or remove
    LogTags &operator =(const LogTags_ot &t) {assert(t < LOG_TYPE_MAX); oldType = t; return *this;}

    /// compute the status access.log field
    const char *c_str() const;

    /// determine if the log tag code indicates a cache HIT
    bool isTcpHit() const;

    /// Things that may happen to a transaction while it is being
    /// processed according to its LOG_* category. Logged as _SUFFIX(es).
    /// Unlike LOG_* categories, these flags may not be mutually exclusive.
    class Errors {
    public:
        Errors() : ignored(false), timedout(false), aborted(false) {}

        bool ignored; ///< _IGNORED: the response was not used for anything
        bool timedout; ///< _TIMEDOUT: terminated due to a lifetime or I/O timeout
        bool aborted;  ///< _ABORTED: other abnormal termination (e.g., I/O error)
    } err;

private:
    /// list of string representations for LogTags_ot
    static const char *Str_[];

public: // XXX: only until client_db.cc stats are redesigned.

    // deprecated LogTag enum value
    LogTags_ot oldType;
};

/// iterator for LogTags_ot enumeration
inline LogTags_ot &operator++ (LogTags_ot &aLogType)
{
    int tmp = (int)aLogType;
    aLogType = (LogTags_ot)(++tmp);
    return aLogType;
}

#endif

