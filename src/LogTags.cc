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
const char * LogTags_str[] = {
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
