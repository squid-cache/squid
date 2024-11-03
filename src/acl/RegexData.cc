/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/*
 * Portions of this code are copyrighted and released under GPLv2+ by:
 * Copyright (c) 2011, Marcus Kool
 * Please add new claims to the CONTRIBUTORS file instead.
 */

/* DEBUG: section 28    Access Control */

#include "squid.h"
#include "acl/Acl.h"
#include "acl/Checklist.h"
#include "acl/RegexData.h"
#include "base/RegexPattern.h"
#include "cache_cf.h"
#include "ConfigParser.h"
#include "debug/Stream.h"
#include "sbuf/Algorithms.h"
#include "sbuf/List.h"
#include "sbuf/Stream.h"

Acl::BooleanOptionValue ACLRegexData::CaseInsensitive_;

ACLRegexData::~ACLRegexData()
{
}

const Acl::Options &
ACLRegexData::lineOptions()
{
    static auto MyCaseSensitivityOption = Acl::CaseSensitivityOption();
    static const Acl::Options MyOptions = { &MyCaseSensitivityOption };
    MyCaseSensitivityOption.linkWith(&CaseInsensitive_);
    return MyOptions;
}

bool
ACLRegexData::match(char const *word)
{
    if (!word)
        return 0;

    debugs(28, 3, "checking '" << word << "'");

    // walk the list of patterns to see if one matches
    for (auto &i : data) {
        if (i.match(word)) {
            debugs(28, 2, '\'' << i << "' found in '" << word << '\'');
            // TODO: old code also popped the pattern to second place of the list
            // in order to reduce patterns search times.
            return 1;
        }
    }

    return 0;
}

SBufList
ACLRegexData::dump() const
{
    SBufStream os;

    const RegexPattern *previous = nullptr;
    for (const auto &i: data) {
        i.print(os, previous); // skip flags implied by the previous entry
        previous = &i;
    }

    return SBufList(1, os.buf());
}

static const char *
removeUnnecessaryWildcards(char * t)
{
    if (strcmp(t, ".*") == 0) // we cannot simplify that further
        return t; // avoid "WARNING: ... Using '.*' instead" below

    char * orig = t;

    if (strncmp(t, "^.*", 3) == 0)
        t += 3;

    /* NOTE: an initial '.' might seem unnessary but is not;
     * it can be a valid requirement that cannot be optimised
     */
    while (*t == '.'  &&  *(t+1) == '*') {
        t += 2;
    }

    if (*t == '\0') {
        debugs(28, DBG_IMPORTANT, cfg_filename << " line " << config_lineno << ": " << config_input_line);
        debugs(28, DBG_IMPORTANT, "WARNING: regular expression '" << orig << "' has only wildcards and matches all strings. Using '.*' instead.");
        return ".*";
    }
    if (t != orig) {
        debugs(28, DBG_IMPORTANT, cfg_filename << " line " << config_lineno << ": " << config_input_line);
        debugs(28, DBG_IMPORTANT, "WARNING: regular expression '" << orig << "' has unnecessary wildcard(s). Using '" << t << "' instead.");
    }

    return t;
}

static void
compileRE(std::list<RegexPattern> &curlist, const SBuf &RE, int flags)
{
    curlist.emplace_back(RE, flags);
}

static void
compileREs(std::list<RegexPattern> &curlist, const SBufList &RE, int flags)
{
    assert(!RE.empty());
    SBuf regexp;
    static const SBuf openparen("("), closeparen(")"), separator(")|(");
    JoinContainerIntoSBuf(regexp, RE.begin(), RE.end(), separator, openparen,
                          closeparen);
    compileRE(curlist, regexp, flags);
}

/** Compose and compile one large RE from a set of (small) REs.
 * The ultimate goal is to have only one RE per ACL so that match() is
 * called only once per ACL.
 */
static void
compileOptimisedREs(std::list<RegexPattern> &curlist, const SBufList &sl, const int flagsAtLineStart)
{
    std::list<RegexPattern> newlist;
    SBufList accumulatedRE;
    int numREs = 0, reSize = 0;
    auto flags = flagsAtLineStart;

    for (const SBuf & configurationLineWord : sl) {
        static const SBuf minus_i("-i");
        static const SBuf plus_i("+i");
        if (configurationLineWord == minus_i) {
            if (flags & REG_ICASE) {
                /* optimisation of  -i ... -i */
                debugs(28, 2, "optimisation of -i ... -i" );
            } else {
                debugs(28, 2, "-i" );
                if (!accumulatedRE.empty()) {
                    compileREs(newlist, accumulatedRE, flags);
                    accumulatedRE.clear();
                    reSize = 0;
                }
                flags |= REG_ICASE;
            }
            continue;
        } else if (configurationLineWord == plus_i) {
            if ((flags & REG_ICASE) == 0) {
                /* optimisation of  +i ... +i */
                debugs(28, 2, "optimisation of +i ... +i");
            } else {
                debugs(28, 2, "+i");
                if (!accumulatedRE.empty()) {
                    compileREs(newlist, accumulatedRE, flags);
                    accumulatedRE.clear();
                    reSize = 0;
                }
                flags &= ~REG_ICASE;
            }
            continue;
        }

        debugs(28, 2, "adding RE '" << configurationLineWord << "'");
        accumulatedRE.push_back(configurationLineWord);
        ++numREs;
        reSize += configurationLineWord.length();

        if (reSize > 1024) { // must be < BUFSIZ everything included
            debugs(28, 2, "buffer full, generating new optimised RE..." );
            compileREs(newlist, accumulatedRE, flags);
            accumulatedRE.clear();
            reSize = 0;
            continue;    /* do the loop again to add the RE to largeRE */
        }
    }

    if (!accumulatedRE.empty()) {
        compileREs(newlist, accumulatedRE, flags);
        accumulatedRE.clear();
        reSize = 0;
    }

    /* all was successful, so put the new list at the tail */
    curlist.splice(curlist.end(), newlist);

    debugs(28, 2, numREs << " REs are optimised into one RE.");
    if (numREs > 100) {
        debugs(28, (opt_parse_cfg_only?DBG_IMPORTANT:2), cfg_filename << " line " << config_lineno << ": " << config_input_line);
        debugs(28, (opt_parse_cfg_only?DBG_IMPORTANT:2), "WARNING: there are more than 100 regular expressions. " <<
               "Consider using less REs or use rules without expressions like 'dstdomain'.");
    }
}

static void
compileUnoptimisedREs(std::list<RegexPattern> &curlist, const SBufList &sl, const int flagsAtLineStart)
{
    auto flags = flagsAtLineStart;

    static const SBuf minus_i("-i"), plus_i("+i");
    for (const auto &configurationLineWord: sl) {
        if (configurationLineWord == minus_i) {
            flags |= REG_ICASE;
        } else if (configurationLineWord == plus_i) {
            flags &= ~REG_ICASE;
        } else {
            compileRE(curlist, configurationLineWord, flags);
        }
    }
}

void
ACLRegexData::parse()
{
    debugs(28, 2, "new Regex line or file");

    int flagsAtLineStart = REG_EXTENDED | REG_NOSUB;
    if (CaseInsensitive_)
        flagsAtLineStart |= REG_ICASE;

    SBufList sl;
    while (char *t = ConfigParser::RegexStrtokFile()) {
        const char *clean = removeUnnecessaryWildcards(t);
        debugs(28, 3, "buffering RE '" << clean << "'");
        sl.emplace_back(clean);
    }

    try {
        // ignore the danger of merging invalid REs into a valid "optimized" RE
        compileOptimisedREs(data, sl, flagsAtLineStart);
    } catch (...) {
        compileUnoptimisedREs(data, sl, flagsAtLineStart);
        // Delay compileOptimisedREs() failure reporting until we know that
        // compileUnoptimisedREs() above have succeeded. If
        // compileUnoptimisedREs() also fails, then the compileOptimisedREs()
        // exception caught earlier was probably not related to _optimization_
        // (and we do not want to report the same RE compilation problem twice).
        debugs(28, DBG_IMPORTANT, "WARNING: Failed to optimize a set of regular expressions; will use them as-is instead;" <<
               Debug::Extra << "configuration: " << cfg_filename << " line " << config_lineno << ": " << config_input_line <<
               Debug::Extra << "optimization error: " << CurrentException);
    }
}

bool
ACLRegexData::empty() const
{
    return data.empty();
}

