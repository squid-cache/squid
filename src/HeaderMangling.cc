/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 66    HTTP Header Tools */

/**
 * Checks the anonymizer (header_access) configuration.
 *
 * \retval 0    Header is explicitly blocked for removal
 * \retval 1    Header is explicitly allowed
 * \retval 1    Header has been replaced, the current version can be used.
 * \retval 1    Header has no access controls to test
 */

#include "squid.h"
#include "acl/FilledChecklist.h"
#include "acl/Gadgets.h"
#include "base/EnumIterator.h"
#include "client_side.h"
#include "client_side_request.h"
#include "comm/Connection.h"
#include "compat/strtoll.h"
#include "ConfigParser.h"
#include "fde.h"
#include "globals.h"
#include "http/RegisteredHeaders.h"
#include "http/Stream.h"
#include "HttpHdrContRange.h"
#include "HttpHeader.h"
#include "http/HeaderTools.h"
#include "HttpRequest.h"
#include "MemBuf.h"
#include "sbuf/Stream.h"
#include "sbuf/StringConvert.h"
#include "SquidConfig.h"
#include "Store.h"
#include "StrList.h"

#if USE_OPENSSL
#include "ssl/support.h"
#endif

#include <algorithm>
#include <cerrno>
#include <string>

static void httpHdrAdd(HttpHeader *heads, HttpRequest *request, const AccessLogEntryPointer &al, HeaderWithAclList &headersAdd);

static int
httpHdrMangle(HttpHeaderEntry * e, HttpRequest * request, HeaderManglers *hms, const AccessLogEntryPointer &al)
{
    int retval;

    assert(e);

    const headerMangler *hm = hms->find(*e);

    /* mangler or checklist went away. default allow */
    if (!hm || !hm->access_list) {
        debugs(66, 7, "couldn't find mangler or access list. Allowing");
        return 1;
    }

    ACLFilledChecklist checklist(hm->access_list, request);
    checklist.updateAle(al);

    // XXX: The two "It was denied" clauses below mishandle cases with no
    // matching rules, violating the "If no rules within the set have matching
    // ACLs, the header field is left as is" promise in squid.conf.
    // TODO: Use Acl::Answer::implicit. See HttpStateData::forwardUpgrade().
    if (checklist.fastCheck().allowed()) {
        /* aclCheckFast returns true for allow. */
        debugs(66, 7, "checklist for mangler is positive. Mangle");
        retval = 1;
    } else if (nullptr == hm->replacement) {
        /* It was denied, and we don't have any replacement */
        debugs(66, 7, "checklist denied, we have no replacement. Pass");
        // XXX: We said "Pass", but the caller will delete on zero retval.
        retval = 0;
    } else {
        /* It was denied, but we have a replacement. Replace the
         * header on the fly, and return that the new header
         * is allowed.
         */
        debugs(66, 7, "checklist denied but we have replacement. Replace");
        e->value = hm->replacement;
        retval = 1;
    }

    return retval;
}

/** Mangles headers for a list of headers. */
void
httpHdrMangleList(HttpHeader *l, HttpRequest *request, const AccessLogEntryPointer &al, req_or_rep_t req_or_rep)
{
    HttpHeaderEntry *e;
    HttpHeaderPos p = HttpHeaderInitPos;

    /* check with anonymizer tables */
    HeaderManglers *hms = nullptr;
    HeaderWithAclList *headersAdd = nullptr;

    switch (req_or_rep) {
    case ROR_REQUEST:
        hms = Config.request_header_access;
        headersAdd = Config.request_header_add;
        break;
    case ROR_REPLY:
        hms = Config.reply_header_access;
        headersAdd = Config.reply_header_add;
        break;
    }

    if (hms) {
        int headers_deleted = 0;
        while ((e = l->getEntry(&p))) {
            if (httpHdrMangle(e, request, hms, al) == 0)
                l->delAt(p, headers_deleted);
        }

        if (headers_deleted)
            l->refreshMask();
    }

    if (headersAdd && !headersAdd->empty()) {
        httpHdrAdd(l, request, al, *headersAdd);
    }
}

static
void header_mangler_clean(headerMangler &m)
{
    aclDestroyAccessList(&m.access_list);
    safe_free(m.replacement);
}

static
void header_mangler_dump_access(StoreEntry * entry, const char *option,
                                const headerMangler &m, const char *name)
{
    if (m.access_list != nullptr) {
        storeAppendPrintf(entry, "%s ", option);
        dump_acl_access(entry, name, m.access_list);
    }
}

static
void header_mangler_dump_replacement(StoreEntry * entry, const char *option,
                                     const headerMangler &m, const char *name)
{
    if (m.replacement)
        storeAppendPrintf(entry, "%s %s %s\n", option, name, m.replacement);
}

HeaderManglers::HeaderManglers()
{
    memset(known, 0, sizeof(known));
    memset(&all, 0, sizeof(all));
}

HeaderManglers::~HeaderManglers()
{
    for (auto i : WholeEnum<Http::HdrType>())
        header_mangler_clean(known[i]);

    for (auto i : custom)
        header_mangler_clean(i.second);

    header_mangler_clean(all);
}

void
HeaderManglers::dumpAccess(StoreEntry * entry, const char *name) const
{
    for (auto id : WholeEnum<Http::HdrType>())
        header_mangler_dump_access(entry, name, known[id], Http::HeaderLookupTable.lookup(id).name);

    for (auto i : custom)
        header_mangler_dump_access(entry, name, i.second, i.first.c_str());

    header_mangler_dump_access(entry, name, all, "All");
}

void
HeaderManglers::dumpReplacement(StoreEntry * entry, const char *name) const
{
    for (auto id : WholeEnum<Http::HdrType>()) {
        header_mangler_dump_replacement(entry, name, known[id], Http::HeaderLookupTable.lookup(id).name);
    }

    for (auto i: custom) {
        header_mangler_dump_replacement(entry, name, i.second, i.first.c_str());
    }

    header_mangler_dump_replacement(entry, name, all, "All");
}

headerMangler *
HeaderManglers::track(const char *name)
{
    if (strcmp(name, "All") == 0)
        return &all;

    const Http::HdrType id = Http::HeaderLookupTable.lookup(SBuf(name)).id;

    if (id != Http::HdrType::BAD_HDR)
        return &known[id];

    if (strcmp(name, "Other") == 0)
        return &known[Http::HdrType::OTHER];

    return &custom[name];
}

void
HeaderManglers::setReplacement(const char *name, const char *value)
{
    // for backword compatibility, we allow replacements to be configured
    // for headers w/o access rules, but such replacements are ignored
    headerMangler *m = track(name);

    safe_free(m->replacement); // overwrite old value if any
    m->replacement = xstrdup(value);
}

const headerMangler *
HeaderManglers::find(const HttpHeaderEntry &e) const
{
    // a known header with a configured ACL list
    if (e.id != Http::HdrType::OTHER && Http::any_HdrType_enum_value(e.id) &&
            known[e.id].access_list)
        return &known[e.id];

    // a custom header
    if (e.id == Http::HdrType::OTHER) {
        // does it have an ACL list configured?
        // Optimize: use a name type that we do not need to convert to here
        SBuf tmp(e.name); // XXX: performance regression. c_str() reallocates
        const ManglersByName::const_iterator i = custom.find(tmp.c_str());
        if (i != custom.end())
            return &i->second;
    }

    // Next-to-last resort: "Other" rules match any custom header
    if (e.id == Http::HdrType::OTHER && known[Http::HdrType::OTHER].access_list)
        return &known[Http::HdrType::OTHER];

    // Last resort: "All" rules match any header
    if (all.access_list)
        return &all;

    return nullptr;
}

void
httpHdrAdd(HttpHeader *heads, HttpRequest *request, const AccessLogEntryPointer &al, HeaderWithAclList &headersAdd)
{
    ACLFilledChecklist checklist(nullptr, request);
    checklist.updateAle(al);

    for (HeaderWithAclList::const_iterator hwa = headersAdd.begin(); hwa != headersAdd.end(); ++hwa) {
        if (!hwa->aclList || checklist.fastCheck(hwa->aclList).allowed()) {
            const char *fieldValue = nullptr;
            MemBuf mb;
            if (hwa->quoted) {
                if (al != nullptr) {
                    mb.init();
                    hwa->valueFormat->assemble(mb, al, 0);
                    fieldValue = mb.content();
                }
            } else {
                fieldValue = hwa->fieldValue.c_str();
            }

            if (!fieldValue || fieldValue[0] == '\0')
                fieldValue = "-";

            HttpHeaderEntry *e = new HttpHeaderEntry(hwa->fieldId, SBuf(hwa->fieldName), fieldValue);
            heads->addEntry(e);
        }
    }
}

