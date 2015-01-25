/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
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
#include "cache_cf.h"
#include "ConfigParser.h"
#include "Debug.h"
#include "HttpHeaderTools.h"
#include "SBuf.h"

/* Construct an ACLHTTPHeaderData that uses an ACLRegex rule with the value of the
 * selected header from a given request.
 *
 * TODO: This can be generalised by making the type of the regex_rule into a
 * template parameter - so that we can use different rules types in future.
 */
ACLHTTPHeaderData::ACLHTTPHeaderData() : hdrId(HDR_BAD_HDR), regex_rule(new ACLRegexData)
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
    if (hdrId != HDR_BAD_HDR) {
        if (!hdr->has(hdrId))
            return false;
        value = hdr->getStrOrList(hdrId);
    } else {
        if (!hdr->getByNameIfPresent(hdrName.termedBuf(), value))
            return false;
    }

    SBuf cvalue(value);
    return regex_rule->match(cvalue.c_str());
}

SBufList
ACLHTTPHeaderData::dump() const
{
    SBufList sl;
    sl.push_back(SBuf(hdrName));
#if __cplusplus >= 201103L
    sl.splice(sl.end(), regex_rule->dump());
#else
    // temp is needed until c++11 move-constructor
    SBufList temp = regex_rule->dump();
    sl.splice(sl.end(), temp);
#endif
    return sl;
}

void
ACLHTTPHeaderData::parse()
{
    char* t = strtokFile();
    assert (t != NULL);
    hdrName = t;
    hdrId = httpHeaderIdByNameDef(hdrName.rawBuf(), hdrName.size());
    regex_rule->parse();
}

bool
ACLHTTPHeaderData::empty() const
{
    return (hdrId == HDR_BAD_HDR && hdrName.size()==0) || regex_rule->empty();
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

