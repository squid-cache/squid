/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "auth/Config.h"
#include "fatal.h"
#include "parser/Tokenizer.h"

static void
addUnique(const SBuf &scheme, std::vector<SBuf> &vec)
{
    static const SBuf all("ALL");
    if (scheme == all) {
        for (const auto config: Auth::TheConfig.schemes)
            addUnique(SBuf(config->type()), vec);
    } else if (std::find(vec.begin(), vec.end(), scheme) == vec.end())
        vec.push_back(scheme);
}

void
Auth::SchemesConfig::expand()
{
    static const CharacterSet delimiters("delimiters", ",");
    static const CharacterSet quotedDelimiters("quotedDelimiters", ", ");
    const CharacterSet *resultDelimiters = quoted ? &quotedDelimiters : &delimiters;
    std::vector<SBuf> expanded;
    Parser::Tokenizer t(schemes);
    SBuf scheme;
    while (t.token(scheme, *resultDelimiters))
        addUnique(scheme, expanded);
    t.skipAllTrailing(CharacterSet::SP + CharacterSet::HTAB);
    if (!t.remaining().isEmpty())
        addUnique(t.remaining(), expanded);

    authConfigs.clear();
    transform(expanded.begin(), expanded.end(),
    back_inserter(authConfigs), [](SBuf &s) {
        return Auth::SchemeConfig::GetParsed(s.c_str());
    });
}

