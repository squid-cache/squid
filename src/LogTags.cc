/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
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
	"TCP_CLIENT_REFRESH_MISS",
	"TCP_IMS_HIT",
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

const char *
LogTags::c_str() const
{
    return Str_[oldType];
}

bool
LogTags::isTcpHit() const
{
    return
        (oldType == LOG_TCP_HIT) ||
        (oldType == LOG_TCP_IMS_HIT) ||
        (oldType == LOG_TCP_REFRESH_FAIL_OLD) ||
        (oldType == LOG_TCP_REFRESH_UNMODIFIED) ||
        (oldType == LOG_TCP_NEGATIVE_HIT) ||
        (oldType == LOG_TCP_MEM_HIT) ||
        (oldType == LOG_TCP_OFFLINE_HIT);
}
