/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 28    Access Control */

#include "squid.h"
#include "acl/ConnMark.h"
#include "acl/FilledChecklist.h"
#include "cache_cf.h"
#include "client_side.h"
#include "Debug.h"
#include "http/Stream.h"
#include "HttpReply.h"
#include "HttpRequest.h"
#include "parser/Tokenizer.h"
#include "Parsing.h"

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

void
ACLConnMark::parse()
{
    while (const char *t = ConfigParser::strtokFile()) {
        SBuf token(t);
        if (token.isEmpty()) {
            continue;
        }

        nfmark_t _mask = 0xffffffff;
        nfmark_t _mark = 0;

        Parser::Tokenizer tokenizer(token);
        int64_t tmp_result;
        // get mark
        if (tokenizer.int64(tmp_result, 0, false))
            _mark = static_cast<nfmark_t>(tmp_result);
        else {
            debugs(28, DBG_CRITICAL, MYNAME << ": bad mark '" << token << "'");
            self_destruct();
        }

        // mark with mask ?
        SBuf::size_type pos = token.find('/');
        if (pos != SBuf::npos) {
            token = SBuf(t + pos + 1);
            tokenizer = Parser::Tokenizer(token);
            if (tokenizer.int64(tmp_result, 0, false))
                _mask = static_cast<nfmark_t>(tmp_result);
            else {
                debugs(28, DBG_CRITICAL, MYNAME << ": bad mask '" << token << "'");
                self_destruct();
            }
        }

        marks.insert(std::pair<nfmark_t, nfmark_t>(_mark, _mask));
        debugs(28, DBG_DATA, MYNAME << ": mark '" << _mark << "/" << _mask << "'");
    }

    if (marks.empty()) {
        debugs(28, DBG_CRITICAL, MYNAME  << ": expect at least one connmark");
        self_destruct();
    }
}

int
ACLConnMark::match(ACLChecklist *cl)
{
    ACLFilledChecklist *checklist = Filled(cl);
    nfmark_t conn_mark = checklist->conn()->clientConnection->nfmark;

    if (marks.empty())
        return -1;

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
    return "connmark";
}
