/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "RegisteredHeaders.h"

#include <ostream>

namespace Http
{

/*
 * A table with major attributes for every known field.
 *
 * Invariant on this table:
 * for each index in HeaderTable, (int)HeaderTable[index] = index
 */
const HeaderTableRecord HeaderTable[] = {
    {"Accept", Http::HdrType::ACCEPT, Http::HdrFieldType::ftStr},
    {"Accept-Charset", Http::HdrType::ACCEPT_CHARSET, Http::HdrFieldType::ftStr},
    {"Accept-Encoding", Http::HdrType::ACCEPT_ENCODING, Http::HdrFieldType::ftStr},
    {"Accept-Language", Http::HdrType::ACCEPT_LANGUAGE, Http::HdrFieldType::ftStr},
    {"Accept-Ranges", Http::HdrType::ACCEPT_RANGES, Http::HdrFieldType::ftStr},
    {"Age", Http::HdrType::AGE, Http::HdrFieldType::ftInt},
    {"Allow", Http::HdrType::ALLOW, Http::HdrFieldType::ftStr},
    {"Alternate-Protocol", Http::HdrType::ALTERNATE_PROTOCOL, Http::HdrFieldType::ftStr},
    {"Authentication-Info", Http::HdrType::AUTHENTICATION_INFO, Http::HdrFieldType::ftStr},
    {"Authorization", Http::HdrType::AUTHORIZATION, Http::HdrFieldType::ftStr},    /* for now */
    {"Cache-Control", Http::HdrType::CACHE_CONTROL, Http::HdrFieldType::ftPCc},
    {"Connection", Http::HdrType::CONNECTION, Http::HdrFieldType::ftStr},
    {"Content-Base", Http::HdrType::CONTENT_BASE, Http::HdrFieldType::ftStr},
    {"Content-Disposition", Http::HdrType::CONTENT_DISPOSITION, Http::HdrFieldType::ftStr},  /* for now */
    {"Content-Encoding", Http::HdrType::CONTENT_ENCODING, Http::HdrFieldType::ftStr},
    {"Content-Language", Http::HdrType::CONTENT_LANGUAGE, Http::HdrFieldType::ftStr},
    {"Content-Length", Http::HdrType::CONTENT_LENGTH, Http::HdrFieldType::ftInt64},
    {"Content-Location", Http::HdrType::CONTENT_LOCATION, Http::HdrFieldType::ftStr},
    {"Content-MD5", Http::HdrType::CONTENT_MD5, Http::HdrFieldType::ftStr},    /* for now */
    {"Content-Range", Http::HdrType::CONTENT_RANGE, Http::HdrFieldType::ftPContRange},
    {"Content-Type", Http::HdrType::CONTENT_TYPE, Http::HdrFieldType::ftStr},
    {"Cookie", Http::HdrType::COOKIE, Http::HdrFieldType::ftStr},
    {"Cookie2", Http::HdrType::COOKIE2, Http::HdrFieldType::ftStr},
    {"Date", Http::HdrType::DATE, Http::HdrFieldType::ftDate_1123},
    {"ETag", Http::HdrType::ETAG, Http::HdrFieldType::ftETag},
    {"Expect", Http::HdrType::EXPECT, Http::HdrFieldType::ftStr},
    {"Expires", Http::HdrType::EXPIRES, Http::HdrFieldType::ftDate_1123},
    {"Forwarded", Http::HdrType::FORWARDED, Http::HdrFieldType::ftStr},
    {"From", Http::HdrType::FROM, Http::HdrFieldType::ftStr},
    {"Host", Http::HdrType::HOST, Http::HdrFieldType::ftStr},
    {"HTTP2-Settings", Http::HdrType::HTTP2_SETTINGS, Http::HdrFieldType::ftStr}, /* for now */
    {"If-Match", Http::HdrType::IF_MATCH, Http::HdrFieldType::ftStr},  /* for now */
    {"If-Modified-Since", Http::HdrType::IF_MODIFIED_SINCE, Http::HdrFieldType::ftDate_1123},
    {"If-None-Match", Http::HdrType::IF_NONE_MATCH, Http::HdrFieldType::ftStr},    /* for now */
    {"If-Range", Http::HdrType::IF_RANGE, Http::HdrFieldType::ftDate_1123_or_ETag},
    {"If-Unmodified-Since", Http::HdrType::IF_UNMODIFIED_SINCE, Http::HdrFieldType::ftDate_1123},
    {"Keep-Alive", Http::HdrType::KEEP_ALIVE, Http::HdrFieldType::ftStr},
    {"Key", Http::HdrType::KEY, Http::HdrFieldType::ftStr},
    {"Last-Modified", Http::HdrType::LAST_MODIFIED, Http::HdrFieldType::ftDate_1123},
    {"Link", Http::HdrType::LINK, Http::HdrFieldType::ftStr},
    {"Location", Http::HdrType::LOCATION, Http::HdrFieldType::ftStr},
    {"Max-Forwards", Http::HdrType::MAX_FORWARDS, Http::HdrFieldType::ftInt64},
    {"Mime-Version", Http::HdrType::MIME_VERSION, Http::HdrFieldType::ftStr},  /* for now */
    {"Negotiate", Http::HdrType::NEGOTIATE, Http::HdrFieldType::ftStr},
    {"Origin", Http::HdrType::ORIGIN, Http::HdrFieldType::ftStr},
    {"Pragma", Http::HdrType::PRAGMA, Http::HdrFieldType::ftStr},
    {"Proxy-Authenticate", Http::HdrType::PROXY_AUTHENTICATE, Http::HdrFieldType::ftStr},
    {"Proxy-Authentication-Info", Http::HdrType::PROXY_AUTHENTICATION_INFO, Http::HdrFieldType::ftStr},
    {"Proxy-Authorization", Http::HdrType::PROXY_AUTHORIZATION, Http::HdrFieldType::ftStr},
    {"Proxy-Connection", Http::HdrType::PROXY_CONNECTION, Http::HdrFieldType::ftStr},
    {"Proxy-support", Http::HdrType::PROXY_SUPPORT, Http::HdrFieldType::ftStr},
    {"Public", Http::HdrType::PUBLIC, Http::HdrFieldType::ftStr},
    {"Range", Http::HdrType::RANGE, Http::HdrFieldType::ftPRange},
    {"Referer", Http::HdrType::REFERER, Http::HdrFieldType::ftStr},
    {"Request-Range", Http::HdrType::REQUEST_RANGE, Http::HdrFieldType::ftPRange}, /* usually matches Http::HdrType::RANGE */
    {"Retry-AHttp::HdrFieldType::fter", Http::HdrType::RETRY_AFTER, Http::HdrFieldType::ftStr},    /* for now (Http::HdrFieldType::ftDate_1123 or Http::HdrFieldType::ftInt!} */
    {"Server", Http::HdrType::SERVER, Http::HdrFieldType::ftStr},
    {"Set-Cookie", Http::HdrType::SET_COOKIE, Http::HdrFieldType::ftStr},
    {"Set-Cookie2", Http::HdrType::SET_COOKIE2, Http::HdrFieldType::ftStr},
    {"TE", Http::HdrType::TE, Http::HdrFieldType::ftStr},
    {"Title", Http::HdrType::TITLE, Http::HdrFieldType::ftStr},
    {"Trailer", Http::HdrType::TRAILER, Http::HdrFieldType::ftStr},
    {"Transfer-Encoding", Http::HdrType::TRANSFER_ENCODING, Http::HdrFieldType::ftStr},
    {"Translate", Http::HdrType::TRANSLATE, Http::HdrFieldType::ftStr},    /* for now. may need to crop */
    {"Unless-Modified-Since", Http::HdrType::UNLESS_MODIFIED_SINCE, Http::HdrFieldType::ftStr},  /* for now ignore. may need to crop */
    {"Upgrade", Http::HdrType::UPGRADE, Http::HdrFieldType::ftStr},    /* for now */
    {"User-Agent", Http::HdrType::USER_AGENT, Http::HdrFieldType::ftStr},
    {"Vary", Http::HdrType::VARY, Http::HdrFieldType::ftStr},  /* for now */
    {"Via", Http::HdrType::VIA, Http::HdrFieldType::ftStr},    /* for now */
    {"Warning", Http::HdrType::WARNING, Http::HdrFieldType::ftStr},    /* for now */
    {"WWW-Authenticate", Http::HdrType::WWW_AUTHENTICATE, Http::HdrFieldType::ftStr},
    {"X-Cache", Http::HdrType::X_CACHE, Http::HdrFieldType::ftStr},
    {"X-Cache-Lookup", Http::HdrType::X_CACHE_LOOKUP, Http::HdrFieldType::ftStr},
    {"X-Forwarded-For", Http::HdrType::X_FORWARDED_FOR, Http::HdrFieldType::ftStr},
    {"X-Request-URI", Http::HdrType::X_REQUEST_URI, Http::HdrFieldType::ftStr},
    {"X-Squid-Error", Http::HdrType::X_SQUID_ERROR, Http::HdrFieldType::ftStr},
#if X_ACCELERATOR_VARY
    {"X-Accelerator-Vary", Http::HdrType::HDR_X_ACCELERATOR_VARY, Http::HdrFieldType::ftStr},
#endif
#if USE_ADAPTATION
    {"X-Next-Services", Http::HdrType::X_NEXT_SERVICES, Http::HdrFieldType::ftStr},
#endif
    {"Surrogate-Capability", Http::HdrType::SURROGATE_CAPABILITY, Http::HdrFieldType::ftStr},
    {"Surrogate-Control", Http::HdrType::SURROGATE_CONTROL, Http::HdrFieldType::ftPSc},
    {"Front-End-Https", Http::HdrType::FRONT_END_HTTPS, Http::HdrFieldType::ftStr},
    {"FTP-Command", Http::HdrType::FTP_COMMAND, Http::HdrFieldType::ftStr},
    {"FTP-Arguments", Http::HdrType::FTP_ARGUMENTS, Http::HdrFieldType::ftStr},
    {"FTP-Pre", Http::HdrType::FTP_PRE, Http::HdrFieldType::ftStr},
    {"FTP-Status", Http::HdrType::FTP_STATUS, Http::HdrFieldType::ftInt},
    {"FTP-Reason", Http::HdrType::FTP_REASON, Http::HdrFieldType::ftStr},
    {"Other:", Http::HdrType::OTHER, Http::HdrFieldType::ftStr},    /* ':' will not allow matches */
    {nullptr, Http::HdrType::ENUM_END, Http::HdrFieldType::ftInvalid},    /* end of table */
    {nullptr, Http::HdrType::BAD_HDR, Http::HdrFieldType::ftInvalid}
};

const LookupTable<Http::HdrType, HeaderTableRecord> HeaderLookupTable(Http::HdrType::BAD_HDR, HeaderTable);

}; /* namespace Http */

extern std::ostream &
operator << (std::ostream &s , Http::HdrType id)
{
    if (id >= Http::HdrType::ACCEPT && id < Http::HdrType::ENUM_END)
        s << Http::HeaderTable[id].name << '(' << static_cast<int>(id) << ')';
    else
        s << "invalid" << '(' << static_cast<int>(id) << ')';
    return s;
}

