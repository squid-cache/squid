/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_HTTPHEADERTOOLS_H
#define SQUID_HTTPHEADERTOOLS_H

#include "acl/forward.h"
#include "format/Format.h"
#include "HttpHeader.h"

#include <functional>
#include <list>
#include <map>
#include <string>
#if HAVE_STRINGS_H
#include <strings.h>
#endif

class HeaderWithAcl;
class HttpHeader;
class HttpRequest;
class StoreEntry;
class String;

typedef std::list<HeaderWithAcl> HeaderWithAclList;

/* Distinguish between Request and Reply (for header mangling) */
typedef enum {
    ROR_REQUEST,
    ROR_REPLY
} req_or_rep_t;

// Currently a POD
class headerMangler
{
public:
    acl_access *access_list;
    char *replacement;
};

/// A collection of headerMangler objects for a given message kind.
class HeaderManglers
{
public:
    HeaderManglers();
    ~HeaderManglers();

    /// returns a header mangler for field e or nil if none was specified
    const headerMangler *find(const HttpHeaderEntry &e) const;

    /// returns a mangler for the named header (known or custom)
    headerMangler *track(const char *name);

    /// updates mangler for the named header with a replacement value
    void setReplacement(const char *name, const char *replacementValue);

    /// report the *_header_access part of the configuration
    void dumpAccess(StoreEntry *entry, const char *optionName) const;
    /// report the *_header_replace part of the configuration
    void dumpReplacement(StoreEntry *entry, const char *optionName) const;

private:
    /// Case-insensitive std::string "less than" comparison functor.
    /// Fast version recommended by Meyers' "Effective STL" for ASCII c-strings.
    class NoCaseLessThan: public std::binary_function<std::string, std::string, bool>
    {
    public:
        bool operator()(const std::string &lhs, const std::string &rhs) const {
            return strcasecmp(lhs.c_str(), rhs.c_str()) < 0;
        }
    };

    /// a name:mangler map; optimize: use unordered map or some such
    typedef std::map<std::string, headerMangler, NoCaseLessThan> ManglersByName;

    /// one mangler for each known header
    headerMangler known[static_cast<int>(Http::HdrType::enumEnd_)];

    /// one mangler for each custom header
    ManglersByName custom;

    /// configured if some mangling ACL applies to all header names
    headerMangler all;

private:
    /* not implemented */
    HeaderManglers(const HeaderManglers &);
    HeaderManglers &operator =(const HeaderManglers &);
};

class HeaderWithAcl
{
public:
    HeaderWithAcl() : aclList(NULL), valueFormat(NULL), fieldId(Http::HdrType::BAD_HDR), quoted(false) {}

    /// HTTP header field name
    std::string fieldName;

    /// HTTP header field value, possibly with macros
    std::string fieldValue;

    /// when the header field should be added (always if nil)
    ACLList *aclList;

    /// compiled HTTP header field value (no macros)
    Format::Format *valueFormat;

    /// internal ID for "known" headers or HDR_OTHER
    Http::HdrType fieldId;

    /// whether fieldValue may contain macros
    bool quoted;
};

/// A strtoll(10) wrapper that checks for strtoll() failures and other problems.
/// XXX: This function is not fully compatible with some HTTP syntax rules.
/// Just like strtoll(), allows whitespace prefix, a sign, and _any_ suffix.
/// Requires at least one digit to be present.
/// Sets "off" and "end" arguments if and only if no problems were found.
/// \return true if and only if no problems were found.
bool httpHeaderParseOffset(const char *start, int64_t *offPtr, char **endPtr = nullptr);

bool httpHeaderHasConnDir(const HttpHeader * hdr, const char *directive);
int httpHeaderParseInt(const char *start, int *val);
void httpHeaderPutStrf(HttpHeader * hdr, Http::HdrType id, const char *fmt,...) PRINTF_FORMAT_ARG3;

const char *getStringPrefix(const char *str, size_t len);

void httpHdrMangleList(HttpHeader *, HttpRequest *, const AccessLogEntryPointer &al, req_or_rep_t req_or_rep);

#endif

