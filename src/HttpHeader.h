/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_HTTPHEADER_H
#define SQUID_HTTPHEADER_H

/* because we pass a spec by value */
#include "HttpHeaderMask.h"
#include "MemPool.h"
#include "SquidString.h"

#include <vector>

/* class forward declarations */
class HttpHdrCc;
class HttpHdrContRange;
class HttpHdrRange;
class HttpHdrSc;
class Packer;
class StoreEntry;
class SBuf;

/* constant attributes of http header fields */

/// recognized or "known" header fields; and the RFC which defines them (or not)
/// http://www.iana.org/assignments/message-headers/message-headers.xhtml
typedef enum {
    HDR_BAD_HDR = -1,
    HDR_ACCEPT = 0,                     /**< RFC 7231 */
    HDR_ACCEPT_CHARSET,                 /**< RFC 7231 */
    HDR_ACCEPT_ENCODING,                /**< RFC 7231 */
    /*HDR_ACCEPT_FEATURES,*/            /* RFC 2295 */
    HDR_ACCEPT_LANGUAGE,                /**< RFC 7231 */
    HDR_ACCEPT_RANGES,                  /**< RFC 7233 */
    HDR_AGE,                            /**< RFC 7234 */
    HDR_ALLOW,                          /**< RFC 7231 */
    HDR_ALTERNATE_PROTOCOL,             /**< GFE custom header we may have to erase */
    HDR_AUTHENTICATION_INFO,            /**< RFC 2617 */
    HDR_AUTHORIZATION,                  /**< RFC 7235, 4559 */
    HDR_CACHE_CONTROL,                  /**< RFC 7234 */
    HDR_CONNECTION,                     /**< RFC 7230 */
    HDR_CONTENT_BASE,                   /**< obsoleted RFC 2068 */
    HDR_CONTENT_DISPOSITION,            /**< RFC 2183, 6266 */
    HDR_CONTENT_ENCODING,               /**< RFC 7231 */
    HDR_CONTENT_LANGUAGE,               /**< RFC 7231 */
    HDR_CONTENT_LENGTH,                 /**< RFC 7230 */
    HDR_CONTENT_LOCATION,               /**< RFC 7231 */
    HDR_CONTENT_MD5,                    /**< deprecated, RFC 2616 */
    HDR_CONTENT_RANGE,                  /**< RFC 7233 */
    HDR_CONTENT_TYPE,                   /**< RFC 7231 */
    HDR_COOKIE,                         /**< RFC 6265 header we may need to erase */
    HDR_COOKIE2,                        /**< obsolete RFC 2965 header we may need to erase */
    HDR_DATE,                           /**< RFC 7231 */
    /*HDR_DAV,*/                        /* RFC 2518 */
    /*HDR_DEPTH,*/                      /* RFC 2518 */
    /*HDR_DERIVED_FROM,*/               /* deprecated RFC 2068 */
    /*HDR_DESTINATION,*/                /* RFC 2518 */
    HDR_ETAG,                           /**< RFC 7232 */
    HDR_EXPECT,                         /**< RFC 7231 */
    HDR_EXPIRES,                        /**< RFC 7234 */
    HDR_FORWARDED,                      /**< RFC 7239 */
    HDR_FROM,                           /**< RFC 7231 */
    HDR_HOST,                           /**< RFC 7230 */
    HDR_HTTP2_SETTINGS,                 /**< RFC 7540 */
    /*HDR_IF,*/                         /* RFC 2518 */
    HDR_IF_MATCH,                       /**< RFC 7232 */
    HDR_IF_MODIFIED_SINCE,              /**< RFC 7232 */
    HDR_IF_NONE_MATCH,                  /**< RFC 7232 */
    HDR_IF_RANGE,                       /**< RFC 7233 */
    HDR_IF_UNMODIFIED_SINCE,            /**< RFC 7232 */
    HDR_KEEP_ALIVE,                     /**< obsoleted RFC 2068 header we may need to erase */
    HDR_KEY,                            /**< experimental RFC Draft draft-fielding-http-key-02 */
    HDR_LAST_MODIFIED,                  /**< RFC 7232 */
    HDR_LINK,                           /**< RFC 5988 */
    HDR_LOCATION,                       /**< RFC 7231 */
    /*HDR_LOCK_TOKEN,*/                 /* RFC 2518 */
    HDR_MAX_FORWARDS,                   /**< RFC 7231 */
    HDR_MIME_VERSION,                   /**< RFC 2045, 7231 */
    HDR_NEGOTIATE,                      /**< experimental RFC 2295. Why only this one from 2295? */
    /*HDR_OVERWRITE,*/                  /* RFC 2518 */
    HDR_ORIGIN,                         /* CORS Draft specification (see http://www.w3.org/TR/cors/) */
    HDR_PRAGMA,                         /**< RFC 7234 */
    HDR_PROXY_AUTHENTICATE,             /**< RFC 7235 */
    HDR_PROXY_AUTHENTICATION_INFO,      /**< RFC 2617 */
    HDR_PROXY_AUTHORIZATION,            /**< RFC 7235 */
    HDR_PROXY_CONNECTION,               /**< obsolete Netscape header we may need to erase. */
    HDR_PROXY_SUPPORT,                  /**< RFC 4559 */
    HDR_PUBLIC,                         /**<  RFC 2068 */
    HDR_RANGE,                          /**< RFC 7233 */
    HDR_REFERER,                        /**< RFC 7231 */
    HDR_REQUEST_RANGE,                  /**< some clients use this, sigh */
    HDR_RETRY_AFTER,                    /**< RFC 7231 */
    HDR_SERVER,                         /**< RFC 7231 */
    HDR_SET_COOKIE,                     /**< RFC 6265 header we may need to erase */
    HDR_SET_COOKIE2,                    /**< obsoleted RFC 2965 header we may need to erase */
    /*HDR_STATUS_URI,*/                 /* RFC 2518 */
    /*HDR_TCN,*/                        /* experimental RFC 2295 */
    HDR_TE,                             /**< RFC 7230 */
    /*HDR_TIMEOUT,*/                    /* RFC 2518 */
    HDR_TITLE,                          /* obsolete draft suggested header */
    HDR_TRAILER,                        /**< RFC 7230 */
    HDR_TRANSFER_ENCODING,              /**< RFC 7230 */
    HDR_TRANSLATE,                      /**< IIS custom header we may need to erase */
    HDR_UNLESS_MODIFIED_SINCE,          /**< IIS custom header we may need to erase */
    HDR_UPGRADE,                        /**< RFC 7230 */
    HDR_USER_AGENT,                     /**< RFC 7231 */
    /*HDR_VARIANT_VARY,*/               /* experimental RFC 2295 */
    HDR_VARY,                           /**< RFC 7231 */
    HDR_VIA,                            /**< RFC 7230 */
    HDR_WARNING,                        /**< RFC 7234 */
    HDR_WWW_AUTHENTICATE,               /**< RFC 7235, 4559 */
    HDR_X_CACHE,                        /**< Squid custom header */
    HDR_X_CACHE_LOOKUP,                 /**< Squid custom header. temporary hack that became de-facto. TODO remove */
    HDR_X_FORWARDED_FOR,                /**< obsolete Squid custom header, RFC 7239 */
    HDR_X_REQUEST_URI,                  /**< Squid custom header appended if ADD_X_REQUEST_URI is defined */
    HDR_X_SQUID_ERROR,                  /**< Squid custom header on generated error responses */
#if X_ACCELERATOR_VARY
    HDR_X_ACCELERATOR_VARY,             /**< obsolete Squid custom header. */
#endif
#if USE_ADAPTATION
    HDR_X_NEXT_SERVICES,                /**< Squid custom ICAP header */
#endif
    HDR_SURROGATE_CAPABILITY,           /**< Edge Side Includes (ESI) header */
    HDR_SURROGATE_CONTROL,              /**< Edge Side Includes (ESI) header */
    HDR_FRONT_END_HTTPS,                /**< MS Exchange custom header we may have to add */
    HDR_FTP_COMMAND,                    /**< Internal header for FTP command */
    HDR_FTP_ARGUMENTS,                  /**< Internal header for FTP command arguments */
    HDR_FTP_PRE,                        /**< Internal header containing leading FTP control response lines */
    HDR_FTP_STATUS,                     /**< Internal header for FTP reply status */
    HDR_FTP_REASON,                     /**< Internal header for FTP reply reason */
    HDR_OTHER,                          /**< internal tag value for "unknown" headers */
    HDR_ENUM_END
} http_hdr_type;

/** possible types for http header fields */
typedef enum {
    ftInvalid = HDR_ENUM_END,   /**< to catch nasty errors with hdr_id<->fld_type clashes */
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
} field_type;

/** Possible owners of http header */
typedef enum {
    hoNone =0,
#if USE_HTCP
    hoHtcpReply,
#endif
    hoRequest,
    hoReply,
#if USE_OPENSSL
    hoErrorDetail,
#endif
    hoEnd
} http_hdr_owner_type;

// currently a POD
class HttpHeaderFieldAttrs
{
public:
    const char *name;
    http_hdr_type id;
    field_type type;
};

/** Iteration for headers; use HttpHeaderPos as opaque type, do not interpret */
typedef ssize_t HttpHeaderPos;

/* use this and only this to initialize HttpHeaderPos */
#define HttpHeaderInitPos (-1)

class HttpHeaderEntry
{

public:
    HttpHeaderEntry(http_hdr_type id, const char *name, const char *value);
    ~HttpHeaderEntry();
    static HttpHeaderEntry *parse(const char *field_start, const char *field_end);
    HttpHeaderEntry *clone() const;
    void packInto(Packer *p) const;
    int getInt() const;
    int64_t getInt64() const;
    MEMPROXY_CLASS(HttpHeaderEntry);
    http_hdr_type id;
    String name;
    String value;
};

MEMPROXY_CLASS_INLINE(HttpHeaderEntry);

class ETag;
class TimeOrTag;

class HttpHeader
{

public:
    HttpHeader();
    explicit HttpHeader(const http_hdr_owner_type owner);
    HttpHeader(const HttpHeader &other);
    ~HttpHeader();

    HttpHeader &operator =(const HttpHeader &other);

    /* Interface functions */
    void clean();
    void append(const HttpHeader * src);
    void update (HttpHeader const *fresh, HttpHeaderMask const *denied_mask);
    void compact();
    int reset();
    int parse(const char *header_start, const char *header_end);
    void packInto(Packer * p, bool mask_sensitive_info=false) const;
    HttpHeaderEntry *getEntry(HttpHeaderPos * pos) const;
    HttpHeaderEntry *findEntry(http_hdr_type id) const;
    int delByName(const char *name);
    int delById(http_hdr_type id);
    void delAt(HttpHeaderPos pos, int &headers_deleted);
    void refreshMask();
    void addEntry(HttpHeaderEntry * e);
    void insertEntry(HttpHeaderEntry * e);
    String getList(http_hdr_type id) const;
    bool getList(http_hdr_type id, String *s) const;
    String getStrOrList(http_hdr_type id) const;
    bool conflictingContentLength() const { return conflictingContentLength_; }
    String getByName(const char *name) const;
    /// sets value and returns true iff a [possibly empty] named field is there
    bool getByNameIfPresent(const char *name, String &value) const;
    String getByNameListMember(const char *name, const char *member, const char separator) const;
    String getListMember(http_hdr_type id, const char *member, const char separator) const;
    int has(http_hdr_type id) const;
    void putInt(http_hdr_type id, int number);
    void putInt64(http_hdr_type id, int64_t number);
    void putTime(http_hdr_type id, time_t htime);
    void insertTime(http_hdr_type id, time_t htime);
    void putStr(http_hdr_type id, const char *str);
    void putAuth(const char *auth_scheme, const char *realm);
    void putCc(const HttpHdrCc * cc);
    void putContRange(const HttpHdrContRange * cr);
    void putRange(const HttpHdrRange * range);
    void putSc(HttpHdrSc *sc);
    void putWarning(const int code, const char *const text); ///< add a Warning header
    void putExt(const char *name, const char *value);
    int getInt(http_hdr_type id) const;
    int64_t getInt64(http_hdr_type id) const;
    time_t getTime(http_hdr_type id) const;
    const char *getStr(http_hdr_type id) const;
    const char *getLastStr(http_hdr_type id) const;
    HttpHdrCc *getCc() const;
    HttpHdrRange *getRange() const;
    HttpHdrSc *getSc() const;
    HttpHdrContRange *getContRange() const;
    const char *getAuth(http_hdr_type id, const char *auth_scheme) const;
    ETag getETag(http_hdr_type id) const;
    TimeOrTag getTimeOrTag(http_hdr_type id) const;
    int hasListMember(http_hdr_type id, const char *member, const char separator) const;
    int hasByNameListMember(const char *name, const char *member, const char separator) const;
    void removeHopByHopEntries();
    inline bool chunked() const; ///< whether message uses chunked Transfer-Encoding

    /* protected, do not use these, use interface functions instead */
    std::vector<HttpHeaderEntry *> entries;     /**< parsed fields in raw format */
    HttpHeaderMask mask;    /**< bit set <=> entry present */
    http_hdr_owner_type owner;  /**< request or reply */
    int len;            /**< length when packed, not counting terminating null-byte */

protected:
    /** \deprecated Public access replaced by removeHopByHopEntries() */
    void removeConnectionHeaderEntries();

private:
    HttpHeaderEntry *findLastEntry(http_hdr_type id) const;
    bool conflictingContentLength_; ///< found different Content-Length fields
};

int httpHeaderParseQuotedString(const char *start, const int len, String *val);

/// quotes string using RFC 7230 quoted-string rules
SBuf httpHeaderQuoteString(const char *raw);

int httpHeaderHasByNameListMember(const HttpHeader * hdr, const char *name, const char *member, const char separator);
void httpHeaderUpdate(HttpHeader * old, const HttpHeader * fresh, const HttpHeaderMask * denied_mask);
void httpHeaderCalcMask(HttpHeaderMask * mask, http_hdr_type http_hdr_type_enums[], size_t count);

inline bool
HttpHeader::chunked() const
{
    return has(HDR_TRANSFER_ENCODING) &&
           hasListMember(HDR_TRANSFER_ENCODING, "chunked", ',');
}

void httpHeaderInitModule(void);
void httpHeaderCleanModule(void);

#endif /* SQUID_HTTPHEADER_H */

