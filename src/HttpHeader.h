/*
 * Copyright (C) 1996-2014 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_HTTPHEADER_H
#define SQUID_HTTPHEADER_H

#include "http/RegisteredHeaders.h"
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

/** possible types for http header fields */
typedef enum {
    ftInvalid = HDR_ENUM_END,	/**< to catch nasty errors with hdr_id<->fld_type clashes */
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
    int parse(const char *header_start, size_t len);
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
    std::vector<HttpHeaderEntry *> entries;		/**< parsed fields in raw format */
    HttpHeaderMask mask;	/**< bit set <=> entry present */
    http_hdr_owner_type owner;	/**< request or reply */
    int len;			/**< length when packed, not counting terminating null-byte */

protected:
    /** \deprecated Public access replaced by removeHopByHopEntries() */
    void removeConnectionHeaderEntries();

private:
    HttpHeaderEntry *findLastEntry(http_hdr_type id) const;
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
