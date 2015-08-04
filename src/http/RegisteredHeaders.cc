/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "RegisteredHeaders.h"

/*
 * A table with major attributes for every known field.
 *
 * Invariant on this table:
 * for each index in headerTable, (int)headerTable[index] = index
 */
const HeaderTableRecord headerTable[] = {
    {"Accept", HDR_ACCEPT, field_type::ftStr},
    {"Accept-Charset", HDR_ACCEPT_CHARSET, field_type::ftStr},
    {"Accept-Encoding", HDR_ACCEPT_ENCODING, field_type::ftStr},
    {"Accept-Language", HDR_ACCEPT_LANGUAGE, field_type::ftStr},
    {"Accept-Ranges", HDR_ACCEPT_RANGES, field_type::ftStr},
    {"Age", HDR_AGE, field_type::ftInt},
    {"Allow", HDR_ALLOW, field_type::ftStr},
    {"Alternate-Protocol", HDR_ALTERNATE_PROTOCOL, field_type::ftStr},
    {"Authentication-Info", HDR_AUTHENTICATION_INFO, field_type::ftStr},
    {"Authorization", HDR_AUTHORIZATION, field_type::ftStr},    /* for now */
    {"Cache-Control", HDR_CACHE_CONTROL, field_type::ftPCc},
    {"Connection", HDR_CONNECTION, field_type::ftStr},
    {"Content-Base", HDR_CONTENT_BASE, field_type::ftStr},
    {"Content-Disposition", HDR_CONTENT_DISPOSITION, field_type::ftStr},  /* for now */
    {"Content-Encoding", HDR_CONTENT_ENCODING, field_type::ftStr},
    {"Content-Language", HDR_CONTENT_LANGUAGE, field_type::ftStr},
    {"Content-Length", HDR_CONTENT_LENGTH, field_type::ftInt64},
    {"Content-Location", HDR_CONTENT_LOCATION, field_type::ftStr},
    {"Content-MD5", HDR_CONTENT_MD5, field_type::ftStr},    /* for now */
    {"Content-Range", HDR_CONTENT_RANGE, field_type::ftPContRange},
    {"Content-Type", HDR_CONTENT_TYPE, field_type::ftStr},
    {"Cookie", HDR_COOKIE, field_type::ftStr},
    {"Cookie2", HDR_COOKIE2, field_type::ftStr},
    {"Date", HDR_DATE, field_type::ftDate_1123},
    {"ETag", HDR_ETAG, field_type::ftETag},
    {"Expect", HDR_EXPECT, field_type::ftStr},
    {"Expires", HDR_EXPIRES, field_type::ftDate_1123},
    {"Forwarded", HDR_FORWARDED, field_type::ftStr},
    {"From", HDR_FROM, field_type::ftStr},
    {"Host", HDR_HOST, field_type::ftStr},
    {"HTTP2-Settings", HDR_HTTP2_SETTINGS, field_type::ftStr}, /* for now */
    {"If-Match", HDR_IF_MATCH, field_type::ftStr},  /* for now */
    {"If-Modified-Since", HDR_IF_MODIFIED_SINCE, field_type::ftDate_1123},
    {"If-None-Match", HDR_IF_NONE_MATCH, field_type::ftStr},    /* for now */
    {"If-Range", HDR_IF_RANGE, field_type::ftDate_1123_or_ETag},
    {"If-Unmodified-Since", HDR_IF_UNMODIFIED_SINCE, field_type::ftDate_1123},
    {"Keep-Alive", HDR_KEEP_ALIVE, field_type::ftStr},
    {"Key", HDR_KEY, field_type::ftStr},
    {"Last-Modified", HDR_LAST_MODIFIED, field_type::ftDate_1123},
    {"Link", HDR_LINK, field_type::ftStr},
    {"Location", HDR_LOCATION, field_type::ftStr},
    {"Max-Forwards", HDR_MAX_FORWARDS, field_type::ftInt64},
    {"Mime-Version", HDR_MIME_VERSION, field_type::ftStr},  /* for now */
    {"Negotiate", HDR_NEGOTIATE, field_type::ftStr},
    {"Origin", HDR_ORIGIN, field_type::ftStr},
    {"Pragma", HDR_PRAGMA, field_type::ftStr},
    {"Proxy-Authenticate", HDR_PROXY_AUTHENTICATE, field_type::ftStr},
    {"Proxy-Authentication-Info", HDR_PROXY_AUTHENTICATION_INFO, field_type::ftStr},
    {"Proxy-Authorization", HDR_PROXY_AUTHORIZATION, field_type::ftStr},
    {"Proxy-Connection", HDR_PROXY_CONNECTION, field_type::ftStr},
    {"Proxy-support", HDR_PROXY_SUPPORT, field_type::ftStr},
    {"Public", HDR_PUBLIC, field_type::ftStr},
    {"Range", HDR_RANGE, field_type::ftPRange},
    {"Referer", HDR_REFERER, field_type::ftStr},
    {"Request-Range", HDR_REQUEST_RANGE, field_type::ftPRange}, /* usually matches HDR_RANGE */
    {"Retry-Afield_type::fter", HDR_RETRY_AFTER, field_type::ftStr},    /* for now (field_type::ftDate_1123 or field_type::ftInt!} */
    {"Server", HDR_SERVER, field_type::ftStr},
    {"Set-Cookie", HDR_SET_COOKIE, field_type::ftStr},
    {"Set-Cookie2", HDR_SET_COOKIE2, field_type::ftStr},
    {"TE", HDR_TE, field_type::ftStr},
    {"Title", HDR_TITLE, field_type::ftStr},
    {"Trailer", HDR_TRAILER, field_type::ftStr},
    {"Transfer-Encoding", HDR_TRANSFER_ENCODING, field_type::ftStr},
    {"Translate", HDR_TRANSLATE, field_type::ftStr},    /* for now. may need to crop */
    {"Unless-Modified-Since", HDR_UNLESS_MODIFIED_SINCE, field_type::ftStr},  /* for now ignore. may need to crop */
    {"Upgrade", HDR_UPGRADE, field_type::ftStr},    /* for now */
    {"User-Agent", HDR_USER_AGENT, field_type::ftStr},
    {"Vary", HDR_VARY, field_type::ftStr},  /* for now */
    {"Via", HDR_VIA, field_type::ftStr},    /* for now */
    {"Warning", HDR_WARNING, field_type::ftStr},    /* for now */
    {"WWW-Authenticate", HDR_WWW_AUTHENTICATE, field_type::ftStr},
    {"X-Cache", HDR_X_CACHE, field_type::ftStr},
    {"X-Cache-Lookup", HDR_X_CACHE_LOOKUP, field_type::ftStr},
    {"X-Forwarded-For", HDR_X_FORWARDED_FOR, field_type::ftStr},
    {"X-Request-URI", HDR_X_REQUEST_URI, field_type::ftStr},
    {"X-Squid-Error", HDR_X_SQUID_ERROR, field_type::ftStr},
#if X_ACCELERATOR_VARY
    {"X-Accelerator-Vary", HDR_X_ACCELERATOR_VARY, field_type::ftStr},
#endif
#if USE_ADAPTATION
    {"X-Next-Services", HDR_X_NEXT_SERVICES, field_type::ftStr},
#endif
    {"Surrogate-Capability", HDR_SURROGATE_CAPABILITY, field_type::ftStr},
    {"Surrogate-Control", HDR_SURROGATE_CONTROL, field_type::ftPSc},
    {"Front-End-Https", HDR_FRONT_END_HTTPS, field_type::ftStr},
    {"FTP-Command", HDR_FTP_COMMAND, field_type::ftStr},
    {"FTP-Arguments", HDR_FTP_ARGUMENTS, field_type::ftStr},
    {"FTP-Pre", HDR_FTP_PRE, field_type::ftStr},
    {"FTP-Status", HDR_FTP_STATUS, field_type::ftInt},
    {"FTP-Reason", HDR_FTP_REASON, field_type::ftStr},
    {"Other:", HDR_OTHER, field_type::ftStr},    /* ':' will not allow matches */
    {nullptr, HDR_BAD_HDR, field_type::ftInvalid}    /* end of table */
};

