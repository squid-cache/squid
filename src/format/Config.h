/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_FORMAT_CONFIG_H
#define SQUID_SRC_FORMAT_CONFIG_H

#include "sbuf/SBuf.h"

#include <list>

namespace Format
{

class TokenTableEntry;

/// A namespace or 'set' of tokens
/// components register their namespace prefix and an array of tokens
/// which can then be embedded in any format.
class TokenNamespace
{
public:
    TokenNamespace(const SBuf &nsName, TokenTableEntry const *tSet) : prefix(nsName), tokenSet(tSet) {}

    /// prefix namespace name (excluding '::')
    SBuf prefix;

    /// array of tokens inside this namespace
    /// The set of tokens may change, but the location of it pointed to from here must not.
    TokenTableEntry const *tokenSet;
};

/// The set of custom formats defined in squid.conf
class FmtConfig
{
public:
    /* Register a namespace set of tokens to be accepted by the format parser.
     * Multiple arrays can be registered, they will be scanned for
     * in order registered. So care needs to be taken that arrays registered
     * first do not overlap or consume tokens registered later for a namespace.
     */
    void registerTokens(const SBuf &nsName, TokenTableEntry const *tokenArray);

    /// list of token namespaces registered
    std::list<TokenNamespace> tokens;
};

extern FmtConfig TheConfig;

} // namespace Format

#endif /* SQUID_SRC_FORMAT_CONFIG_H */

