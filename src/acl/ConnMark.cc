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

static std::ostream &
operator <<(std::ostream &os, const Acl::ConnMark::ConnMarkQuery connmark)
{
    os << AsHex<nfmark_t>(connmark.first);
    if (connmark.second != 0xffffffff) {
        os << '/' << AsHex<nfmark_t>(connmark.second);
    }
    return os;
}

nfmark_t
Acl::ConnMark::getNumber(Parser::Tokenizer &tokenizer, const SBuf &token) const
{
    int64_t number;
    if (!tokenizer.int64(number, 0, false)) {
        throw TexcHere(ToSBuf("acl ", typeString(), ": invalid value '", tokenizer.buf(), "' in ", token));
    }

    if (number > std::numeric_limits<nfmark_t>::max()) {
        throw TexcHere(ToSBuf("acl ", typeString(), ": number ", number, " in ", token, " is too big"));
    }
    return static_cast<nfmark_t>(number);
}

void
Acl::ConnMark::parse()
{
    while (const char *t = ConfigParser::strtokFile()) {
        SBuf token(t);
        Parser::Tokenizer tokenizer(token);

        const auto mark = getNumber(tokenizer, token);
        const auto mask = tokenizer.skip('/') ? getNumber(tokenizer, token) : 0xffffffff;

        if (!tokenizer.atEnd()) {
            throw TexcHere(ToSBuf("acl ", typeString(), ": trailing garbage in ", token));
        }

        const ConnMarkQuery connmark(mark, mask);
        marks.push_back(connmark);
        debugs(28, 7, "mark '" << connmark << "'");
    }

    if (marks.empty()) {
        throw TexcHere(ToSBuf("acl ", typeString(), " requires at least one mark"));
    }
}

int
Acl::ConnMark::match(ACLChecklist *cl)
{
    const auto *checklist = Filled(cl);
    const auto connmark = checklist->conn()->clientConnection->nfmark;

    for (const auto &m : marks) {
        if ((connmark & m.second) == m.first) {
            debugs(28, 7, "CONNMARK '" << AsHex<nfmark_t>(connmark) << "' matches with '" << m << "'");
            return 1;
        }
        debugs(28, 7, "checking CONNMARK '" << AsHex<nfmark_t>(connmark) << "' against '" << m << "'");
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
    return "clientside_mark";
}
