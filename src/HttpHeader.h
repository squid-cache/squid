/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_HTTPHEADER_H
#define SQUID_HTTPHEADER_H

#include "anyp/ProtocolVersion.h"
#include "base/LookupTable.h"
#include "http/RegisteredHeaders.h"
/* because we pass a spec by value */
#include "HttpHeaderMask.h"
#include "mem/PoolingAllocator.h"
#include "sbuf/forward.h"
#include "SquidString.h"

#include <vector>

/* class forward declarations */
class HttpHdrCc;
class HttpHdrContRange;
class HttpHdrRange;
class HttpHdrSc;
class Packable;

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

/** Iteration for headers; use HttpHeaderPos as opaque type, do not interpret */
typedef ssize_t HttpHeaderPos;

/* use this and only this to initialize HttpHeaderPos */
#define HttpHeaderInitPos (-1)

class HttpHeaderEntry
{
    MEMPROXY_CLASS(HttpHeaderEntry);

public:
    HttpHeaderEntry(Http::HdrType id, const SBuf &name, const char *value);
    ~HttpHeaderEntry();
    static HttpHeaderEntry *parse(const char *field_start, const char *field_end);
    HttpHeaderEntry *clone() const;
    void packInto(Packable *p) const;
    int getInt() const;
    int64_t getInt64() const;

    Http::HdrType id;
    SBuf name;
    String value;
};

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
    bool update(HttpHeader const *fresh);
    void compact();
    int parse(const char *header_start, size_t len, Http::ContentLengthInterpreter &interpreter);
    /// Parses headers stored in a buffer.
    /// \returns 1 and sets hdr_sz on success
    /// \returns 0 when needs more data
    /// \returns -1 on error
    int parse(const char *buf, size_t buf_len, bool atEnd, size_t &hdr_sz, Http::ContentLengthInterpreter &interpreter);
    void packInto(Packable * p, bool mask_sensitive_info=false) const;
    HttpHeaderEntry *getEntry(HttpHeaderPos * pos) const;
    HttpHeaderEntry *findEntry(Http::HdrType id) const;
    /// deletes all fields with a given name, if any.
    /// \return #fields deleted
    int delByName(const SBuf &name);
    /// \deprecated use SBuf method instead. performance regression: reallocates
    int delByName(const char *name) { return delByName(SBuf(name)); }
    int delById(Http::HdrType id);
    void delAt(HttpHeaderPos pos, int &headers_deleted);
    void refreshMask();
    void addEntry(HttpHeaderEntry * e);
    void insertEntry(HttpHeaderEntry * e);
    String getList(Http::HdrType id) const;
    bool getList(Http::HdrType id, String *s) const;
    bool conflictingContentLength() const { return conflictingContentLength_; }
    String getStrOrList(Http::HdrType id) const;
    String getByName(const SBuf &name) const;
    String getByName(const char *name) const;
    String getById(Http::HdrType id) const;
    /// returns true iff a [possibly empty] field identified by id is there
    /// when returning true, also sets the `result` parameter (if it is not nil)
    bool getByIdIfPresent(Http::HdrType id, String *result) const;
    /// returns true iff a [possibly empty] named field is there
    /// when returning true, also sets the `value` parameter (if it is not nil)
    bool hasNamed(const SBuf &s, String *value = 0) const;
    /// \deprecated use SBuf method instead.
    bool hasNamed(const char *name, unsigned int namelen, String *value = 0) const;
    SBuf getByNameListMember(const char *name, const char *member, const char separator) const;
    SBuf getListMember(Http::HdrType id, const char *member, const char separator) const;
    int has(Http::HdrType id) const;
    /// Appends "this cache" information to VIA header field.
    /// Takes the initial VIA value from "from" parameter, if provided.
    void addVia(const AnyP::ProtocolVersion &ver, const HttpHeader *from = 0);
    void putInt(Http::HdrType id, int number);
    void putInt64(Http::HdrType id, int64_t number);
    void putTime(Http::HdrType id, time_t htime);
    void putStr(Http::HdrType id, const char *str);
    void putAuth(const char *auth_scheme, const char *realm);
    void putCc(const HttpHdrCc * cc);
    void putContRange(const HttpHdrContRange * cr);
    void putRange(const HttpHdrRange * range);
    void putSc(HttpHdrSc *sc);
    void putWarning(const int code, const char *const text); ///< add a Warning header
    void putExt(const char *name, const char *value);
    int getInt(Http::HdrType id) const;
    int64_t getInt64(Http::HdrType id) const;
    time_t getTime(Http::HdrType id) const;
    const char *getStr(Http::HdrType id) const;
    const char *getLastStr(Http::HdrType id) const;
    HttpHdrCc *getCc() const;
    HttpHdrRange *getRange() const;
    HttpHdrSc *getSc() const;
    HttpHdrContRange *getContRange() const;
    const char *getAuth(Http::HdrType id, const char *auth_scheme) const;
    ETag getETag(Http::HdrType id) const;
    TimeOrTag getTimeOrTag(Http::HdrType id) const;
    int hasListMember(Http::HdrType id, const char *member, const char separator) const;
    int hasByNameListMember(const char *name, const char *member, const char separator) const;
    void removeHopByHopEntries();
    inline bool chunked() const; ///< whether message uses chunked Transfer-Encoding

    /* protected, do not use these, use interface functions instead */
    std::vector<HttpHeaderEntry*, PoolingAllocator<HttpHeaderEntry*> > entries; /**< parsed fields in raw format */
    HttpHeaderMask mask;    /**< bit set <=> entry present */
    http_hdr_owner_type owner;  /**< request or reply */
    int len;            /**< length when packed, not counting terminating null-byte */

protected:
    /** \deprecated Public access replaced by removeHopByHopEntries() */
    void removeConnectionHeaderEntries();
    /// either finds the end of headers or returns false
    /// If the end was found:
    /// *parse_start points to the first character after the header delimiter
    /// *blk_start points to the first header character (i.e. old parse_start value)
    /// *blk_end points to the first header delimiter character (CR or LF in CR?LF).
    /// If block starts where it ends, then there are no fields in the header.
    static bool Isolate(const char **parse_start, size_t l, const char **blk_start, const char **blk_end);
    bool needUpdate(const HttpHeader *fresh) const;
    bool skipUpdateHeader(const Http::HdrType id) const;
    void updateWarnings();

private:
    HttpHeaderEntry *findLastEntry(Http::HdrType id) const;
    bool conflictingContentLength_; ///< found different Content-Length fields
};

int httpHeaderParseQuotedString(const char *start, const int len, String *val);

/// quotes string using RFC 7230 quoted-string rules
SBuf httpHeaderQuoteString(const char *raw);

void httpHeaderCalcMask(HttpHeaderMask * mask, Http::HdrType http_hdr_type_enums[], size_t count);

inline bool
HttpHeader::chunked() const
{
    return has(Http::HdrType::TRANSFER_ENCODING) &&
           hasListMember(Http::HdrType::TRANSFER_ENCODING, "chunked", ',');
}

void httpHeaderInitModule(void);

#endif /* SQUID_HTTPHEADER_H */

