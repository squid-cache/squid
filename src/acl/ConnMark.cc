/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 28    Access Control */

#include "squid.h"
#include "acl/ConnMark.h"
#include "acl/FilledChecklist.h"
#include "client_side.h"
#include "Debug.h"
#include "http/Stream.h"
#include "sbuf/Stream.h"

bool
Acl::ConnMark::empty() const
{
    return false;
}

void
Acl::ConnMark::parse()
{
    while (const char *t = ConfigParser::strtokFile()) {
        SBuf token(t);
        Parser::Tokenizer tokenizer(token);
        const auto mc = Ip::NfMarkConfig::Parse(token);
        marks.push_back(mc);
        debugs(28, 7, "added " << mc);
    }

    if (marks.empty()) {
        throw TexcHere(ToSBuf("acl ", typeString(), " requires at least one mark"));
    }
}

int
Acl::ConnMark::match(ACLChecklist *cl)
{
    const auto *checklist = Filled(cl);
    const auto connmark = checklist->conn()->clientConnection->nfConnmark;

    for (const auto &m : marks) {
        if (m.matches(connmark)) {
            debugs(28, 5, "found " << m << " matching " << asHex(connmark));
            return 1;
        }
        debugs(28, 7, "skipped " << m << " mismatching " << asHex(connmark));
    }
    return 0;
}

SBufList
Acl::ConnMark::dump() const
{
    SBufList sl;
    for (const auto &m : marks) {
        sl.push_back(ToSBuf(m));
    }
    return sl;
}

char const *
Acl::ConnMark::typeString() const
{
    return "client_connection_mark";
}

