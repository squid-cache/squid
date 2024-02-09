/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 28    Access Control */

#include "squid.h"
#include "acl/ConnMark.h"
#include "acl/FilledChecklist.h"
#include "base/IoManip.h"
#include "client_side.h"
#include "debug/Stream.h"
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
    const auto conn = checklist->conn();

    if (conn && conn->clientConnection) {
        const auto connmark = conn->clientConnection->nfConnmark;

        for (const auto &m : marks) {
            if (m.matches(connmark)) {
                debugs(28, 5, "found " << m << " matching 0x" << asHex(connmark));
                return 1;
            }
            debugs(28, 7, "skipped " << m << " mismatching 0x" << asHex(connmark));
        }
    } else {
        debugs(28, 7, "fails: no client connection");
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

