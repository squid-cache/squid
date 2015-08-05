/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_HTTP_REGISTEREDHEADERS_H
#define SQUID_HTTP_REGISTEREDHEADERS_H

#include "base/LookupTable.h"
#include <iosfwd>

namespace Http
{
/// recognized or "known" header fields; and the RFC which defines them (or not)
/// http://www.iana.org/assignments/message-headers/message-headers.xhtml
enum HdrType {
    ACCEPT = 0,                     /**< RFC 7231 */ /* MUST BE FIRST */
    ACCEPT_CHARSET,                 /**< RFC 7231 */
    ACCEPT_ENCODING,                /**< RFC 7231 */
    /*ACCEPT_FEATURES,*/            /* RFC 2295 */
    ACCEPT_LANGUAGE,                /**< RFC 7231 */
    ACCEPT_RANGES,                  /**< RFC 7233 */
    AGE,                            /**< RFC 7234 */
    ALLOW,                          /**< RFC 7231 */
    ALTERNATE_PROTOCOL,             /**< GFE custom header we may have to erase */
    AUTHENTICATION_INFO,            /**< RFC 2617 */
    AUTHORIZATION,                  /**< RFC 7235, 4559 */
    CACHE_CONTROL,                  /**< RFC 7234 */
    CONNECTION,                     /**< RFC 7230 */
    CONTENT_BASE,                   /**< obsoleted RFC 2068 */
    CONTENT_DISPOSITION,            /**< RFC 2183, 6266 */
    CONTENT_ENCODING,               /**< RFC 7231 */
    CONTENT_LANGUAGE,               /**< RFC 7231 */
    CONTENT_LENGTH,                 /**< RFC 7230 */
    CONTENT_LOCATION,               /**< RFC 7231 */
    CONTENT_MD5,                    /**< deprecated, RFC 2616 */
    CONTENT_RANGE,                  /**< RFC 7233 */
    CONTENT_TYPE,                   /**< RFC 7231 */
    COOKIE,                         /**< RFC 6265 header we may need to erase */
    COOKIE2,                        /**< obsolete RFC 2965 header we may need to erase */
    DATE,                           /**< RFC 7231 */
    /*DAV,*/                        /* RFC 2518 */
    /*DEPTH,*/                      /* RFC 2518 */
    /*DERIVED_FROM,*/               /* deprecated RFC 2068 */
    /*DESTINATION,*/                /* RFC 2518 */
    ETAG,                           /**< RFC 7232 */
    EXPECT,                         /**< RFC 7231 */
    EXPIRES,                        /**< RFC 7234 */
    FORWARDED,                      /**< RFC 7239 */
    FROM,                           /**< RFC 7231 */
    HOST,                           /**< RFC 7230 */
    HTTP2_SETTINGS,                 /**< RFC 7540 */
    /*IF,*/                         /* RFC 2518 */
    IF_MATCH,                       /**< RFC 7232 */
    IF_MODIFIED_SINCE,              /**< RFC 7232 */
    IF_NONE_MATCH,                  /**< RFC 7232 */
    IF_RANGE,                       /**< RFC 7233 */
    IF_UNMODIFIED_SINCE,            /**< RFC 7232 */
    KEEP_ALIVE,                     /**< obsoleted RFC 2068 header we may need to erase */
    KEY,                            /**< experimental RFC Draft draft-fielding-http-key-02 */
    LAST_MODIFIED,                  /**< RFC 7232 */
    LINK,                           /**< RFC 5988 */
    LOCATION,                       /**< RFC 7231 */
    /*LOCK_TOKEN,*/                 /* RFC 2518 */
    MAX_FORWARDS,                   /**< RFC 7231 */
    MIME_VERSION,                   /**< RFC 2045, 7231 */
    NEGOTIATE,                      /**< experimental RFC 2295. Why only this one from 2295? */
    /*OVERWRITE,*/                  /* RFC 2518 */
    ORIGIN,                         /* CORS Draft specification (see http://www.w3.org/TR/cors/) */
    PRAGMA,                         /**< RFC 7234 */
    PROXY_AUTHENTICATE,             /**< RFC 7235 */
    PROXY_AUTHENTICATION_INFO,      /**< RFC 2617 */
    PROXY_AUTHORIZATION,            /**< RFC 7235 */
    PROXY_CONNECTION,               /**< obsolete Netscape header we may need to erase. */
    PROXY_SUPPORT,                  /**< RFC 4559 */
    PUBLIC,                         /**<  RFC 2068 */
    RANGE,                          /**< RFC 7233 */
    REFERER,                        /**< RFC 7231 */
    REQUEST_RANGE,                  /**< some clients use this, sigh */
    RETRY_AFTER,                    /**< RFC 7231 */
    SERVER,                         /**< RFC 7231 */
    SET_COOKIE,                     /**< RFC 6265 header we may need to erase */
    SET_COOKIE2,                    /**< obsoleted RFC 2965 header we may need to erase */
    /*STATUS_URI,*/                 /* RFC 2518 */
    /*TCN,*/                        /* experimental RFC 2295 */
    TE,                             /**< RFC 7230 */
    /*TIMEOUT,*/                    /* RFC 2518 */
    TITLE,                          /* obsolete draft suggested header */
    TRAILER,                        /**< RFC 7230 */
    TRANSFER_ENCODING,              /**< RFC 7230 */
    TRANSLATE,                      /**< IIS custom header we may need to erase */
    UNLESS_MODIFIED_SINCE,          /**< IIS custom header we may need to erase */
    UPGRADE,                        /**< RFC 7230 */
    USER_AGENT,                     /**< RFC 7231 */
    /*VARIANT_VARY,*/               /* experimental RFC 2295 */
    VARY,                           /**< RFC 7231 */
    VIA,                            /**< RFC 7230 */
    WARNING,                        /**< RFC 7234 */
    WWW_AUTHENTICATE,               /**< RFC 7235, 4559 */
    X_CACHE,                        /**< Squid custom header */
    X_CACHE_LOOKUP,                 /**< Squid custom header. temporary hack that became de-facto. TODO remove */
    X_FORWARDED_FOR,                /**< obsolete Squid custom header, RFC 7239 */
    X_REQUEST_URI,                  /**< Squid custom header appended if ADD_X_REQUEST_URI is defined */
    X_SQUID_ERROR,                  /**< Squid custom header on generated error responses */
#if X_ACCELERATOR_VARY
    HDR_X_ACCELERATOR_VARY,             /**< obsolete Squid custom header. */
#endif
#if USE_ADAPTATION
    X_NEXT_SERVICES,                /**< Squid custom ICAP header */
#endif
    SURROGATE_CAPABILITY,           /**< Edge Side Includes (ESI) header */
    SURROGATE_CONTROL,              /**< Edge Side Includes (ESI) header */
    FRONT_END_HTTPS,                /**< MS Exchange custom header we may have to add */
    FTP_COMMAND,                    /**< Internal header for FTP command */
    FTP_ARGUMENTS,                  /**< Internal header for FTP command arguments */
    FTP_PRE,                        /**< Internal header containing leading FTP control response lines */
    FTP_STATUS,                     /**< Internal header for FTP reply status */
    FTP_REASON,                     /**< Internal header for FTP reply reason */
    OTHER,                          /**< internal tag value for "unknown" headers */
    ENUM_END,                       /**< internal tag for end-of-valid headers */
    BAD_HDR                         /**< Invalid header. Must be after ENUM_END */
};

/** possible types for http header fields */
enum class HdrFieldType {
    ftInvalid,  /**< to catch nasty errors with hdr_id<->fld_type clashes */
    ftInt,
    ftInt64,
    ftStr,
    ftDate_1123,
    ftETag,
    ftPCc,
    ftPContRange,
    ftPRange,
    ftPSc,
    ftDate_1123_or_ETag
};

/* POD for HeaderTable */
class HeaderTableRecord {
public:
    const char *name;
    Http::HdrType id;
    Http::HdrFieldType type;
};

/// header ID->namelookup table.
extern const HeaderTableRecord HeaderTable[];

/** LookupTable for HTTP Header name -> Http::HdrType lookup.
 *
 * use as HeaderLookupTable.lookup(header-as-sbuf).
 * It will return Http::HdrType::HDR_BAD if the header is unknown/not registered,
 * including the case of Http::HdrType::OTHER, which will have to be handled
 * by the caller.
 */
extern const LookupTable<Http::HdrType, HeaderTableRecord> HeaderLookupTable;

inline bool
any_HdrType_enum_value (const Http::HdrType id)
{
    return (id == Http::HdrType::BAD_HDR || (id >= Http::HdrType::ACCEPT && id < Http::HdrType::ENUM_END));
}

inline bool
any_valid_header (const Http::HdrType id)
{
    return (id >= Http::HdrType::ACCEPT && id < Http::HdrType::ENUM_END);
}

}; /* namespace Http */

std::ostream &
operator << (std::ostream &, Http::HdrType);

#endif /* SQUID_HTTP_REGISTEREDHEADERS_H */

