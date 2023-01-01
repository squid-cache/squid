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
#include "ConfigParser.h"
#include "Debug.h"
#include "sbuf/Algorithms.h"
#include "sbuf/List.h"

ACLRegexData::~ACLRegexData()
{
}

const Acl::ParameterFlags &
ACLRegexData::supportedFlags() const
{
    static const Acl::ParameterFlags flags = { "-i", "+i" };
    return flags;
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
            debugs(28, 2, '\'' << i.c_str() << "' found in '" << word << '\'');
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
    SBufList sl;
    int flags = REG_EXTENDED | REG_NOSUB;

    // walk and dump the list
    // keeping the flags values consistent
    for (auto &i : data) {
        if (i.flags != flags) {
            if ((i.flags&REG_ICASE) != 0) {
                sl.emplace_back("-i");
            } else {
                sl.emplace_back("+i");
            }
            flags = i.flags;
        }

        sl.emplace_back(i.c_str());
    }

    return sl;
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

static bool
compileRE(std::list<RegexPattern> &curlist, const char * RE, int flags)
{
    if (RE == NULL || *RE == '\0')
        return curlist.empty(); // XXX: old code did this. It looks wrong.

    regex_t comp;
    if (int errcode = regcomp(&comp, RE, flags)) {
        char errbuf[256];
        regerror(errcode, &comp, errbuf, sizeof errbuf);
        debugs(28, DBG_CRITICAL, cfg_filename << " line " << config_lineno << ": " << config_input_line);
        debugs(28, DBG_CRITICAL, "ERROR: invalid regular expression: '" << RE << "': " << errbuf);
        return false;
    }
    debugs(28, 2, "compiled '" << RE << "' with flags " << flags);

    curlist.emplace_back(flags, RE);
    curlist.back().regex = comp;

    return true;
}

static bool
compileRE(std::list<RegexPattern> &curlist, const SBufList &RE, int flags)
{
    if (RE.empty())
        return curlist.empty(); // XXX: old code did this. It looks wrong.
    SBuf regexp;
    static const SBuf openparen("("), closeparen(")"), separator(")|(");
    JoinContainerIntoSBuf(regexp, RE.begin(), RE.end(), separator, openparen,
                          closeparen);
    return compileRE(curlist, regexp.c_str(), flags);
}

/** Compose and compile one large RE from a set of (small) REs.
 * The ultimate goal is to have only one RE per ACL so that match() is
 * called only once per ACL.
 */
static int
compileOptimisedREs(std::list<RegexPattern> &curlist, const SBufList &sl)
{
    std::list<RegexPattern> newlist;
    SBufList accumulatedRE;
    int numREs = 0, reSize = 0;
    int flags = REG_EXTENDED | REG_NOSUB;

    for (const SBuf & configurationLineWord : sl) {
        static const SBuf minus_i("-i");
        static const SBuf plus_i("+i");
        if (configurationLineWord == minus_i) {
            if (flags & REG_ICASE) {
                /* optimisation of  -i ... -i */
                debugs(28, 2, "optimisation of -i ... -i" );
            } else {
                debugs(28, 2, "-i" );
                if (!compileRE(newlist, accumulatedRE, flags))
                    return 0;
                flags |= REG_ICASE;
                accumulatedRE.clear();
                reSize = 0;
            }
            continue;
        } else if (configurationLineWord == plus_i) {
            if ((flags & REG_ICASE) == 0) {
                /* optimisation of  +i ... +i */
                debugs(28, 2, "optimisation of +i ... +i");
            } else {
                debugs(28, 2, "+i");
                if (!compileRE(newlist, accumulatedRE, flags))
                    return 0;
                flags &= ~REG_ICASE;
                accumulatedRE.clear();
                reSize = 0;
            }
            continue;
        }

        debugs(28, 2, "adding RE '" << configurationLineWord << "'");
        accumulatedRE.push_back(configurationLineWord);
        ++numREs;
        reSize += configurationLineWord.length();

        if (reSize > 1024) { // must be < BUFSIZ everything included
            debugs(28, 2, "buffer full, generating new optimised RE..." );
            if (!compileRE(newlist, accumulatedRE, flags))
                return 0;
            accumulatedRE.clear();
            reSize = 0;
            continue;    /* do the loop again to add the RE to largeRE */
        }
    }

    if (!compileRE(newlist, accumulatedRE, flags))
        return 0;

    accumulatedRE.clear();
    reSize = 0;

    /* all was successful, so put the new list at the tail */
    curlist.splice(curlist.end(), newlist);

    debugs(28, 2, numREs << " REs are optimised into one RE.");
    if (numREs > 100) {
        debugs(28, (opt_parse_cfg_only?DBG_IMPORTANT:2), cfg_filename << " line " << config_lineno << ": " << config_input_line);
        debugs(28, (opt_parse_cfg_only?DBG_IMPORTANT:2), "WARNING: there are more than 100 regular expressions. " <<
               "Consider using less REs or use rules without expressions like 'dstdomain'.");
    }

    return 1;
}

static void
compileUnoptimisedREs(std::list<RegexPattern> &curlist, const SBufList &sl)
{
    int flags = REG_EXTENDED | REG_NOSUB;

    static const SBuf minus_i("-i"), plus_i("+i");
    for (auto configurationLineWord : sl) {
        if (configurationLineWord == minus_i) {
            flags |= REG_ICASE;
        } else if (configurationLineWord == plus_i) {
            flags &= ~REG_ICASE;
        } else {
            if (!compileRE(curlist, configurationLineWord.c_str(), flags))
                debugs(28, DBG_CRITICAL, "ERROR: Skipping regular expression. "
                       "Compile failed: '" << configurationLineWord << "'");
        }
    }
}

void
ACLRegexData::parse()
{
    debugs(28, 2, "new Regex line or file");

    SBufList sl;
    while (char *t = ConfigParser::RegexStrtokFile()) {
        const char *clean = removeUnnecessaryWildcards(t);
        if (strlen(clean) > BUFSIZ-1) {
            debugs(28, DBG_CRITICAL, cfg_filename << " line " << config_lineno << ": " << config_input_line);
            debugs(28, DBG_CRITICAL, "ERROR: Skipping regular expression. Larger than " << BUFSIZ-1 << " characters: '" << clean << "'");
        } else {
            debugs(28, 3, "buffering RE '" << clean << "'");
            sl.emplace_back(clean);
        }
    }

    if (!compileOptimisedREs(data, sl)) {
        debugs(28, DBG_IMPORTANT, "WARNING: optimisation of regular expressions failed; using fallback method without optimisation");
        compileUnoptimisedREs(data, sl);
    }
}

bool
ACLRegexData::empty() const
{
    return data.empty();
}

ACLData<char const *> *
ACLRegexData::clone() const
{
    /* Regex's don't clone yet. */
    assert(data.empty());
    return new ACLRegexData;
}

