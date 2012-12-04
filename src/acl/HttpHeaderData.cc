/*
 * DEBUG: section 28    Access Control
 * AUTHOR: Duane Wessels
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
 *
 * Copyright (c) 2003, Robert Collins <robertc@squid-cache.org>
 */

#include "squid.h"
#include "acl/HttpHeaderData.h"
#include "acl/Checklist.h"
#include "acl/Acl.h"
#include "acl/RegexData.h"
#include "cache_cf.h"
#include "Debug.h"
#include "wordlist.h"
#include "ConfigParser.h"
#include "HttpHeaderTools.h"

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

    // By now, we know the header is present, but:
    // HttpHeader::get*() return an undefined String for empty header values;
    // String::termedBuf() returns NULL for undefined Strings; and
    // ACLRegexData::match() always fails on NULL strings.
    // This makes it possible to detect an empty header value using regex:
    const char *cvalue = value.defined() ? value.termedBuf() : "";
    return regex_rule->match(cvalue);
}

wordlist *
ACLHTTPHeaderData::dump()
{
    wordlist *W = NULL;
    wordlistAdd(&W, hdrName.termedBuf());
    wordlist * regex_dump = regex_rule->dump();
    wordlistAddWl(&W, regex_dump);
    wordlistDestroy(&regex_dump);
    return W;
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
    return (hdrId == HDR_BAD_HDR && hdrName.undefined()) || regex_rule->empty();
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
