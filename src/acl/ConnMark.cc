/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 28    Access Control */

#include "squid.h"
#include "acl/FilledChecklist.h"
#include "acl/ConnMark.h"
#include "cache_cf.h"
#include "Debug.h"

#include "client_side.h"
#include "http/Stream.h"
#include "HttpReply.h"
#include "HttpRequest.h"

#include <string>


ACLConnMark::ACLConnMark() {}

ACL *
ACLConnMark::clone() const
{
    return new ACLConnMark(*this);
}

bool
ACLConnMark::empty () const
{
    return false;
}

uint32_t
strToInt(std::string s)
{
    uint32_t num = 0;
    try {
        num = std::stoul(s, nullptr, 0);
    } catch(...) {
        debugs(28, DBG_CRITICAL, "bad number '" << s << "'");
    }

    return num;
}

void
ACLConnMark::parse()
{
    while (char *t = ConfigParser::strtokFile()) {
	std::string token(t);
	if (token.empty()) {
		continue;
	}
	uint32_t _mask = 0xffffffff;
        uint32_t _mark = 0;
	size_t p = token.find("/");
        if (p != std::string::npos) {
            // mark with mask
	    _mark = strToInt(token.substr(0,p));
	    _mask = strToInt(token.substr(p+1));
        } else {
            // single mark
            _mark = strToInt(token);
	}

        if ((_mark == 0 && _mask == 0xffffffff) || (_mask == 0)) {
            debugs(28, DBG_CRITICAL, "aclParseConnMark: bad mark '" << t << "'");
	    self_destruct();
        } else {
            // save mark and mask
	    marks.insert(std::pair<uint32_t, uint32_t>(_mark, _mask));
	}
    }

    if (marks.empty()) {
        debugs(28, DBG_CRITICAL, "aclParseConnMark: expect at least one connmark");
        self_destruct();
    }
}

int
ACLConnMark::match(ACLChecklist *cl)
{
    ACLFilledChecklist *checklist = Filled(cl);
    uint32_t conn_mark = checklist->conn()->getClientConnection()->client_nfmark;

    if (marks.empty()) {
        return 1;
    }

    for (auto m : marks) {
        if ((conn_mark & m.second) == m.first) {
           return 1;
       }
    }
    return 0;
}

SBufList
ACLConnMark::dump() const
{
    SBufList sl;
    for (auto m : marks) {
        SBuf s;
        s.Printf("0x%08x/0x%08x", m.first, m.second);
        sl.push_back(s);
    }
    return sl;
}

char const *
ACLConnMark::typeString() const
{
    return "client_connmark";
}
