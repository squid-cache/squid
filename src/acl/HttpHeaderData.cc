/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 28    Access Control */

#include "squid.h"
#include "acl/Acl.h"
#include "acl/Checklist.h"
#include "acl/HttpHeaderData.h"
#include "acl/RegexData.h"
#include "base/RegexPattern.h"
#include "ConfigParser.h"
#include "Debug.h"
#include "HttpHeaderTools.h"
#include "sbuf/SBuf.h"
#include "sbuf/StringConvert.h"

/* Construct an ACLHTTPHeaderData that uses an ACLRegex rule with the value of the
 * selected header from a given request.
 *
 * TODO: This can be generalised by making the type of the regex_rule into a
 * template parameter - so that we can use different rules types in future.
 */
ACLHTTPHeaderData::ACLHTTPHeaderData() : hdrId(Http::HdrType::BAD_HDR), regex_rule(new ACLRegexData)
{}

ACLHTTPHeaderData::~ACLHTTPHeaderData()
{
    delete regex_rule;
}

bool
ACLHTTPHeaderData::match(HttpHeader* hdr)
{
    if (hdr == NULL)
        return false;

    debugs(28, 3, "aclHeaderData::match: checking '" << hdrName << "'");

    String value;
    if (hdrId != Http::HdrType::BAD_HDR) {
        if (!hdr->has(hdrId))
            return false;
        value = hdr->getStrOrList(hdrId);
    } else {
        if (!hdr->hasNamed(hdrName, &value))
            return false;
    }

    auto cvalue = StringToSBuf(value);
    return regex_rule->match(cvalue.c_str());
}

SBufList
ACLHTTPHeaderData::dump() const
{
    SBufList sl;
    sl.push_back(SBuf(hdrName));
    sl.splice(sl.end(), regex_rule->dump());
    return sl;
}

void
ACLHTTPHeaderData::parse()
{
    char* t = ConfigParser::strtokFile();
    if (!t) {
        debugs(28, DBG_CRITICAL, "ERROR: " << cfg_filename << " line " << config_lineno << ": " << config_input_line);
        debugs(28, DBG_CRITICAL, "ERROR: Missing header name in ACL");
        return;
    }

    if (hdrName.isEmpty()) {
        hdrName = t;
        hdrId = Http::HeaderLookupTable.lookup(hdrName).id;
    } else if (hdrName.caseCmp(t) != 0) {
        debugs(28, DBG_CRITICAL, "ERROR: " << cfg_filename << " line " << config_lineno << ": " << config_input_line);
        debugs(28, DBG_CRITICAL, "ERROR: ACL cannot match both " << hdrName << " and " << t << " headers. Use 'anyof' ACL instead.");
        return;
    }

    regex_rule->parse();
}

bool
ACLHTTPHeaderData::empty() const
{
    return (hdrId == Http::HdrType::BAD_HDR && hdrName.isEmpty()) || regex_rule->empty();
}

ACLData<HttpHeader*> *
ACLHTTPHeaderData::clone() const
{
    /* Header's don't clone yet. */
    ACLHTTPHeaderData * result = new ACLHTTPHeaderData;
    result->regex_rule = regex_rule->clone();
    result->hdrId = hdrId;
    result->hdrName = hdrName;
    return result;
}

