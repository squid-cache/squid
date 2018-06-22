/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "comm/Connection.h"
#include "errorpage.h"
#include "clients/HttpTunnelerAnswer.h"

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

    os << ']';
    return os;
}
