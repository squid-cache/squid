/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "auth/bearer/Token.h"
#include "base/ClpMap.h"
#include "sbuf/Algorithms.h"

// TTL 1 hour for any entry, or 256KB of cached data
Auth::Bearer::TokenCache Auth::Bearer::Token::Cache(60*60, 256*1024);

uint64_t
Auth::Bearer::MemoryUsedByToken(const TokenPointer &t)
{
    return t->b68encoded.length() + sizeof(Token);
}
