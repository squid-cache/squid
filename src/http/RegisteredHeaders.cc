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

/*
 * A table with major attributes for every known field.
 *
 * Invariant on this table:
 * for each index in headerTable, (int)headerTable[index] = index
 */
const HeaderTableRecord headerTable[] = {
    {"Accept", Http::HdrType::ACCEPT, field_type::ftStr},
    {"Accept-Charset", Http::HdrType::ACCEPT_CHARSET, field_type::ftStr},
    {"Accept-Encoding", Http::HdrType::ACCEPT_ENCODING, field_type::ftStr},
    {"Accept-Language", Http::HdrType::ACCEPT_LANGUAGE, field_type::ftStr},
    {"Accept-Ranges", Http::HdrType::ACCEPT_RANGES, field_type::ftStr},
    {"Age", Http::HdrType::AGE, field_type::ftInt},
    {"Allow", Http::HdrType::ALLOW, field_type::ftStr},
    {"Alternate-Protocol", Http::HdrType::ALTERNATE_PROTOCOL, field_type::ftStr},
    {"Authentication-Info", Http::HdrType::AUTHENTICATION_INFO, field_type::ftStr},
    {"Authorization", Http::HdrType::AUTHORIZATION, field_type::ftStr},    /* for now */
    {"Cache-Control", Http::HdrType::CACHE_CONTROL, field_type::ftPCc},
    {"Connection", Http::HdrType::CONNECTION, field_type::ftStr},
    {"Content-Base", Http::HdrType::CONTENT_BASE, field_type::ftStr},
    {"Content-Disposition", Http::HdrType::CONTENT_DISPOSITION, field_type::ftStr},  /* for now */
    {"Content-Encoding", Http::HdrType::CONTENT_ENCODING, field_type::ftStr},
    {"Content-Language", Http::HdrType::CONTENT_LANGUAGE, field_type::ftStr},
    {"Content-Length", Http::HdrType::CONTENT_LENGTH, field_type::ftInt64},
    {"Content-Location", Http::HdrType::CONTENT_LOCATION, field_type::ftStr},
    {"Content-MD5", Http::HdrType::CONTENT_MD5, field_type::ftStr},    /* for now */
    {"Content-Range", Http::HdrType::CONTENT_RANGE, field_type::ftPContRange},
    {"Content-Type", Http::HdrType::CONTENT_TYPE, field_type::ftStr},
    {"Cookie", Http::HdrType::COOKIE, field_type::ftStr},
    {"Cookie2", Http::HdrType::COOKIE2, field_type::ftStr},
    {"Date", Http::HdrType::DATE, field_type::ftDate_1123},
    {"ETag", Http::HdrType::ETAG, field_type::ftETag},
    {"Expect", Http::HdrType::EXPECT, field_type::ftStr},
    {"Expires", Http::HdrType::EXPIRES, field_type::ftDate_1123},
    {"Forwarded", Http::HdrType::FORWARDED, field_type::ftStr},
    {"From", Http::HdrType::FROM, field_type::ftStr},
    {"Host", Http::HdrType::HOST, field_type::ftStr},
    {"HTTP2-Settings", Http::HdrType::HTTP2_SETTINGS, field_type::ftStr}, /* for now */
    {"If-Match", Http::HdrType::IF_MATCH, field_type::ftStr},  /* for now */
    {"If-Modified-Since", Http::HdrType::IF_MODIFIED_SINCE, field_type::ftDate_1123},
    {"If-None-Match", Http::HdrType::IF_NONE_MATCH, field_type::ftStr},    /* for now */
    {"If-Range", Http::HdrType::IF_RANGE, field_type::ftDate_1123_or_ETag},
    {"If-Unmodified-Since", Http::HdrType::IF_UNMODIFIED_SINCE, field_type::ftDate_1123},
    {"Keep-Alive", Http::HdrType::KEEP_ALIVE, field_type::ftStr},
    {"Key", Http::HdrType::KEY, field_type::ftStr},
    {"Last-Modified", Http::HdrType::LAST_MODIFIED, field_type::ftDate_1123},
    {"Link", Http::HdrType::LINK, field_type::ftStr},
    {"Location", Http::HdrType::LOCATION, field_type::ftStr},
    {"Max-Forwards", Http::HdrType::MAX_FORWARDS, field_type::ftInt64},
    {"Mime-Version", Http::HdrType::MIME_VERSION, field_type::ftStr},  /* for now */
    {"Negotiate", Http::HdrType::NEGOTIATE, field_type::ftStr},
    {"Origin", Http::HdrType::ORIGIN, field_type::ftStr},
    {"Pragma", Http::HdrType::PRAGMA, field_type::ftStr},
    {"Proxy-Authenticate", Http::HdrType::PROXY_AUTHENTICATE, field_type::ftStr},
    {"Proxy-Authentication-Info", Http::HdrType::PROXY_AUTHENTICATION_INFO, field_type::ftStr},
    {"Proxy-Authorization", Http::HdrType::PROXY_AUTHORIZATION, field_type::ftStr},
    {"Proxy-Connection", Http::HdrType::PROXY_CONNECTION, field_type::ftStr},
    {"Proxy-support", Http::HdrType::PROXY_SUPPORT, field_type::ftStr},
    {"Public", Http::HdrType::PUBLIC, field_type::ftStr},
    {"Range", Http::HdrType::RANGE, field_type::ftPRange},
    {"Referer", Http::HdrType::REFERER, field_type::ftStr},
    {"Request-Range", Http::HdrType::REQUEST_RANGE, field_type::ftPRange}, /* usually matches Http::HdrType::RANGE */
    {"Retry-Afield_type::fter", Http::HdrType::RETRY_AFTER, field_type::ftStr},    /* for now (field_type::ftDate_1123 or field_type::ftInt!} */
    {"Server", Http::HdrType::SERVER, field_type::ftStr},
    {"Set-Cookie", Http::HdrType::SET_COOKIE, field_type::ftStr},
    {"Set-Cookie2", Http::HdrType::SET_COOKIE2, field_type::ftStr},
    {"TE", Http::HdrType::TE, field_type::ftStr},
    {"Title", Http::HdrType::TITLE, field_type::ftStr},
    {"Trailer", Http::HdrType::TRAILER, field_type::ftStr},
    {"Transfer-Encoding", Http::HdrType::TRANSFER_ENCODING, field_type::ftStr},
    {"Translate", Http::HdrType::TRANSLATE, field_type::ftStr},    /* for now. may need to crop */
    {"Unless-Modified-Since", Http::HdrType::UNLESS_MODIFIED_SINCE, field_type::ftStr},  /* for now ignore. may need to crop */
    {"Upgrade", Http::HdrType::UPGRADE, field_type::ftStr},    /* for now */
    {"User-Agent", Http::HdrType::USER_AGENT, field_type::ftStr},
    {"Vary", Http::HdrType::VARY, field_type::ftStr},  /* for now */
    {"Via", Http::HdrType::VIA, field_type::ftStr},    /* for now */
    {"Warning", Http::HdrType::WARNING, field_type::ftStr},    /* for now */
    {"WWW-Authenticate", Http::HdrType::WWW_AUTHENTICATE, field_type::ftStr},
    {"X-Cache", Http::HdrType::X_CACHE, field_type::ftStr},
    {"X-Cache-Lookup", Http::HdrType::X_CACHE_LOOKUP, field_type::ftStr},
    {"X-Forwarded-For", Http::HdrType::X_FORWARDED_FOR, field_type::ftStr},
    {"X-Request-URI", Http::HdrType::X_REQUEST_URI, field_type::ftStr},
    {"X-Squid-Error", Http::HdrType::X_SQUID_ERROR, field_type::ftStr},
#if X_ACCELERATOR_VARY
    {"X-Accelerator-Vary", Http::HdrType::HDR_X_ACCELERATOR_VARY, field_type::ftStr},
#endif
#if USE_ADAPTATION
    {"X-Next-Services", Http::HdrType::X_NEXT_SERVICES, field_type::ftStr},
#endif
    {"Surrogate-Capability", Http::HdrType::SURROGATE_CAPABILITY, field_type::ftStr},
    {"Surrogate-Control", Http::HdrType::SURROGATE_CONTROL, field_type::ftPSc},
    {"Front-End-Https", Http::HdrType::FRONT_END_HTTPS, field_type::ftStr},
    {"FTP-Command", Http::HdrType::FTP_COMMAND, field_type::ftStr},
    {"FTP-Arguments", Http::HdrType::FTP_ARGUMENTS, field_type::ftStr},
    {"FTP-Pre", Http::HdrType::FTP_PRE, field_type::ftStr},
    {"FTP-Status", Http::HdrType::FTP_STATUS, field_type::ftInt},
    {"FTP-Reason", Http::HdrType::FTP_REASON, field_type::ftStr},
    {"Other:", Http::HdrType::OTHER, field_type::ftStr},    /* ':' will not allow matches */
    {nullptr, Http::HdrType::ENUM_END, field_type::ftInvalid},    /* end of table */
    {nullptr, Http::HdrType::BAD_HDR, field_type::ftInvalid}
};

const LookupTable<Http::HdrType, HeaderTableRecord> HeaderLookupTable(Http::HdrType::BAD_HDR, headerTable);

extern std::ostream &
operator << (std::ostream &s , Http::HdrType id)
{
    // id is guaranteed to be valid by strong type-safety
    s << HeaderById(id).name << '(' << static_cast<int>(id) << ')';
    return s;
}

const HeaderTableRecord&
HeaderById(Http::HdrType id)
{
    return headerTable[static_cast<int>(id)];
}
