/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
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
#include "typedefs.h"

#include <functional>
#include <list>
#include <map>
#include <string>
#if HAVE_STRINGS_H
#include <strings.h>
#endif

class HeaderWithAcl;
class HttpHeader;
class HttpHeaderFieldInfo;
class HttpRequest;
class StoreEntry;
class String;

typedef std::list<HeaderWithAcl> HeaderWithAclList;

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
    headerMangler known[HDR_ENUM_END];

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
    HeaderWithAcl() : aclList(NULL), valueFormat(NULL), fieldId(HDR_BAD_HDR), quoted(false) {}

    /// HTTP header field name
    std::string fieldName;

    /// HTTP header field value, possibly with macros
    std::string fieldValue;

    /// when the header field should be added (always if nil)
    ACLList *aclList;

    /// compiled HTTP header field value (no macros)
    Format::Format *valueFormat;

    /// internal ID for "known" headers or HDR_OTHER
    http_hdr_type fieldId;

    /// whether fieldValue may contain macros
    bool quoted;
};

int httpHeaderParseOffset(const char *start, int64_t * off);

HttpHeaderFieldInfo *httpHeaderBuildFieldsInfo(const HttpHeaderFieldAttrs * attrs, int count);
void httpHeaderDestroyFieldsInfo(HttpHeaderFieldInfo * info, int count);
http_hdr_type httpHeaderIdByName(const char *name, size_t name_len, const HttpHeaderFieldInfo * attrs, int end);
http_hdr_type httpHeaderIdByNameDef(const char *name, int name_len);
const char *httpHeaderNameById(int id);
int httpHeaderHasConnDir(const HttpHeader * hdr, const char *directive);
int httpHeaderParseInt(const char *start, int *val);
void httpHeaderPutStrf(HttpHeader * hdr, http_hdr_type id, const char *fmt,...) PRINTF_FORMAT_ARG3;

const char *getStringPrefix(const char *str, const char *end);

void httpHdrMangleList(HttpHeader *, HttpRequest *, int req_or_rep);

#endif

