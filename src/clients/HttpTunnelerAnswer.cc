/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "clients/HttpTunnelerAnswer.h"
#include "comm/Connection.h"
#include "errorpage.h"

Http::TunnelerAnswer::~TunnelerAnswer()
{
    delete squidError.get();
}

std::ostream &
Http::operator <<(std::ostream &os, const TunnelerAnswer &answer)
{
    os << '[';

    if (const auto squidError = answer.squidError.get()) {
        os << "SquidErr:" << squidError->page_id;
    } else {
        os << "OK";
        if (const auto extraBytes = answer.leftovers.length())
            os << '+' << extraBytes;
    }

    if (answer.peerResponseStatus != Http::scNone)
        os << ' ' << answer.peerResponseStatus;

    if (answer.conn)
        os << ' ' << answer.conn;

    os << ']';
    return os;
}

