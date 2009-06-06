
/*
 * $Id: HttpHeader.h,v 1.24.2.1 2008/02/27 05:59:29 amosjeffries Exp $
 *
 *
 * SQUID Web Proxy Cache          http://www.squid-cache.org/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from
 *  the Internet community; see the CONTRIBUTORS file for full
 *  details.   Many organizations have provided support for Squid's
 *  development; see the SPONSORS file for full details.  Squid is
 *  Copyrighted (C) 2001 by the Regents of the University of
 *  California; see the COPYRIGHT file for full details.  Squid
 *  incorporates software developed and/or copyrighted by other
 *  sources; see the CREDITS file for full details.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *  
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *  
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111, USA.
 *
 */

#ifndef SQUID_HTTPHEADER_H
#define SQUID_HTTPHEADER_H

/* forward decls */

class CacheManager;
/* because we pass a spec by value */
#include "HttpHeaderRange.h"
/* HttpHeader holds a HttpHeaderMask */
#include "HttpHeaderMask.h"

/* constant attributes of http header fields */

/* recognized or "known" header fields; @?@ add more! */
typedef enum {
    HDR_BAD_HDR = -1,
    HDR_ACCEPT = 0,
    HDR_ACCEPT_CHARSET,
    HDR_ACCEPT_ENCODING,
    HDR_ACCEPT_LANGUAGE,
    HDR_ACCEPT_RANGES,
    HDR_AGE,
    HDR_ALLOW,
    HDR_AUTHORIZATION,
    HDR_CACHE_CONTROL,
    HDR_CONNECTION,
    HDR_CONTENT_BASE,
    HDR_CONTENT_DISPOSITION,
    HDR_CONTENT_ENCODING,
    HDR_CONTENT_LANGUAGE,
    HDR_CONTENT_LENGTH,
    HDR_CONTENT_LOCATION,
    HDR_CONTENT_MD5,
    HDR_CONTENT_RANGE,
    HDR_CONTENT_TYPE,
    HDR_COOKIE,
    HDR_DATE,
    HDR_ETAG,
    HDR_EXPIRES,
    HDR_FROM,
    HDR_HOST,
    HDR_IF_MATCH,
    HDR_IF_MODIFIED_SINCE,
    HDR_IF_NONE_MATCH,
    HDR_IF_RANGE,
    HDR_KEEP_ALIVE,
    HDR_LAST_MODIFIED,
    HDR_LINK,
    HDR_LOCATION,
    HDR_MAX_FORWARDS,
    HDR_MIME_VERSION,
    HDR_PRAGMA,
    HDR_PROXY_AUTHENTICATE,
    HDR_PROXY_AUTHENTICATION_INFO,
    HDR_PROXY_AUTHORIZATION,
    HDR_PROXY_CONNECTION,
    HDR_PUBLIC,
    HDR_RANGE,
    HDR_REQUEST_RANGE,		/* some clients use this, sigh */
    HDR_REFERER,
    HDR_RETRY_AFTER,
    HDR_SERVER,
    HDR_SET_COOKIE,
    HDR_TE,
    HDR_TITLE,
    HDR_TRAILERS,
    HDR_TRANSFER_ENCODING,
    HDR_TRANSLATE,             /* IIS custom header we may need to cut off */
    HDR_UNLESS_MODIFIED_SINCE,             /* IIS custom header we may need to cut off */
    HDR_UPGRADE,
    HDR_USER_AGENT,
    HDR_VARY,
    HDR_VIA,
    HDR_WARNING,
    HDR_WWW_AUTHENTICATE,
    HDR_AUTHENTICATION_INFO,
    HDR_X_CACHE,
    HDR_X_CACHE_LOOKUP,		/* tmp hack, remove later */
    HDR_X_FORWARDED_FOR,
    HDR_X_REQUEST_URI,		/* appended if ADD_X_REQUEST_URI is #defined */
    HDR_X_SQUID_ERROR,
    HDR_NEGOTIATE,
#if X_ACCELERATOR_VARY
    HDR_X_ACCELERATOR_VARY,
#endif
    HDR_SURROGATE_CAPABILITY,
    HDR_SURROGATE_CONTROL,
    HDR_FRONT_END_HTTPS,
    HDR_OTHER,
    HDR_ENUM_END
} http_hdr_type;

/* possible types for http header fields */
typedef enum {
    ftInvalid = HDR_ENUM_END,	/* to catch nasty errors with hdr_id<->fld_type clashes */
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

/* possible owners of http header */
typedef enum {
    hoNone =0,
#if USE_HTCP
    hoHtcpReply,
#endif
    hoRequest,
    hoReply
} http_hdr_owner_type;

struct _HttpHeaderFieldAttrs
{
    const char *name;
    http_hdr_type id;
    field_type type;
};

class HttpVersion;

class HttpHdrContRange;

class HttpHdrCc;

class HttpHdrSc;

/*iteration for headers; use HttpHeaderPos as opaque type, do not interpret */
typedef ssize_t HttpHeaderPos;

/* use this and only this to initialize HttpHeaderPos */
#define HttpHeaderInitPos (-1)

/* these two are defined in  structs.h */

typedef struct _TimeOrTag TimeOrTag;

typedef struct _ETag ETag;

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

MEMPROXY_CLASS_INLINE(HttpHeaderEntry)

class HttpHeader
{

public:
    HttpHeader();
    HttpHeader(http_hdr_owner_type const &owner);
    ~HttpHeader();
    /* Interface functions */
    void clean();
    void append(const HttpHeader * src);
    void update (HttpHeader const *fresh, HttpHeaderMask const *denied_mask);
    void compact();
    int reset();
    int parse(const char *header_start, const char *header_end);
    void packInto(Packer * p) const;
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
    String getByName(const char *name) const;
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
    void removeConnectionHeaderEntries();
    /* protected, do not use these, use interface functions instead */
    Vector<HttpHeaderEntry *> entries;		/* parsed fields in raw format */
    HttpHeaderMask mask;	/* bit set <=> entry present */
    http_hdr_owner_type owner;	/* request or reply */
    int len;			/* length when packed, not counting terminating '\0' */

private:
    HttpHeaderEntry *findLastEntry(http_hdr_type id) const;
    // Make it non-copyable. Our destructor is a bit nasty...
    HttpHeader(const HttpHeader &);
    //assignment is used by the reset method, can't block it..
    //const HttpHeader operator=(const HttpHeader &);
};


extern void httpHeaderRegisterWithCacheManager(CacheManager & manager);
extern int httpHeaderParseQuotedString (const char *start, String *val);
SQUIDCEXTERN int httpHeaderHasByNameListMember(const HttpHeader * hdr, const char *name, const char *member, const char separator);
SQUIDCEXTERN void httpHeaderUpdate(HttpHeader * old, const HttpHeader * fresh, const HttpHeaderMask * denied_mask);
int httpMsgIsPersistent(HttpVersion const &http_ver, const HttpHeader * hdr);

SQUIDCEXTERN void httpHeaderCalcMask(HttpHeaderMask * mask, http_hdr_type http_hdr_type_enums[], size_t count);

#endif /* SQUID_HTTPHEADER_H */
