/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
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
#include "wordlist.h"

ACLRegexData::~ACLRegexData()
{
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
            debugs(28, 2, "'" << i.c_str() << "' found in '" << word << "'");
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
    auto flags = std::regex::extended | std::regex::nosubs;

    // walk and dump the list
    // keeping the flags values consistent
    for (auto &i : data) {
        if (i.flags != flags) {
            if ((i.flags & std::regex::icase)) {
                sl.push_back(SBuf("-i"));
            } else {
                sl.push_back(SBuf("+i"));
            }
            flags = i.flags;
        }

        sl.push_back(SBuf(i.c_str()));
    }

    return sl;
}

static const char *
removeUnnecessaryWildcards(char * t)
{
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
        debugs(28, DBG_IMPORTANT, "" << cfg_filename << " line " << config_lineno << ": " << config_input_line);
        debugs(28, DBG_IMPORTANT, "WARNING: regular expression '" << orig << "' has only wildcards and matches all strings. Using '.*' instead.");
        return ".*";
    }
    if (t != orig) {
        debugs(28, DBG_IMPORTANT, "" << cfg_filename << " line " << config_lineno << ": " << config_input_line);
        debugs(28, DBG_IMPORTANT, "WARNING: regular expression '" << orig << "' has unnecessary wildcard(s). Using '" << t << "' instead.");
    }

    return t;
}

static bool
compileRE(std::list<RegexPattern> &curlist, const char * RE, const decltype(RegexPattern::flags) &flags)
{
    if (RE == NULL || *RE == '\0')
        return curlist.empty(); // XXX: old code did this. It looks wrong.

    // std::regex constructor does the actual compile and throws on invalid patterns
    try {
        curlist.emplace_back(flags, RE);

    } catch(std::regex_error &e) {
        debugs(28, DBG_CRITICAL, "" << cfg_filename << " line " << config_lineno << ": " << config_input_line);
        debugs(28, DBG_CRITICAL, "ERROR: invalid regular expression: '" << RE << "': " << e.code());
        return false;

    } catch(...) {
        debugs(28, DBG_CRITICAL, "" << cfg_filename << " line " << config_lineno << ": " << config_input_line);
        debugs(28, DBG_CRITICAL, "ERROR: invalid regular expression: '" << RE << "': (unknown error)");
        return false;
    }

    debugs(28, 2, "compiled '" << RE << "' with flags " << flags);
    return true;
}

/** Compose and compile one large RE from a set of (small) REs.
 * The ultimate goal is to have only one RE per ACL so that regexec() is
 * called only once per ACL.
 */
static int
compileOptimisedREs(std::list<RegexPattern> &curlist, wordlist * wl)
{
    std::list<RegexPattern> newlist;
    int numREs = 0;
    auto flags = std::regex::extended | std::regex::nosubs;
    int largeREindex = 0;
    char largeRE[BUFSIZ];
    *largeRE = 0;

    while (wl != NULL) {
        int RElen;
        RElen = strlen( wl->key );

        if (strcmp(wl->key, "-i") == 0) {
            if ((flags & std::regex::icase)) {
                /* optimisation of  -i ... -i */
                debugs(28, 2, "optimisation of -i ... -i" );
            } else {
                debugs(28, 2, "-i" );
                if (!compileRE(newlist, largeRE, flags))
                    return 0;
                flags |= std::regex::icase;
                largeRE[largeREindex=0] = '\0';
            }
        } else if (strcmp(wl->key, "+i") == 0) {
            if (!(flags & std::regex::icase)) {
                /* optimisation of  +i ... +i */
                debugs(28, 2, "optimisation of +i ... +i");
            } else {
                debugs(28, 2, "+i");
                if (!compileRE(newlist, largeRE, flags))
                    return 0;
                flags &= ~std::regex::icase;
                largeRE[largeREindex=0] = '\0';
            }
        } else if (RElen + largeREindex + 3 < BUFSIZ-1) {
            debugs(28, 2, "adding RE '" << wl->key << "'");
            if (largeREindex > 0) {
                largeRE[largeREindex] = '|';
                ++largeREindex;
            }
            largeRE[largeREindex] = '(';
            ++largeREindex;
            for (char * t = wl->key; *t != '\0'; ++t) {
                largeRE[largeREindex] = *t;
                ++largeREindex;
            }
            largeRE[largeREindex] = ')';
            ++largeREindex;
            largeRE[largeREindex] = '\0';
            ++numREs;
        } else {
            debugs(28, 2, "buffer full, generating new optimised RE..." );
            if (!compileRE(newlist, largeRE, flags))
                return 0;
            largeRE[largeREindex=0] = '\0';
            continue;    /* do the loop again to add the RE to largeRE */
        }
        wl = wl->next;
    }

    if (!compileRE(newlist, largeRE, flags))
        return 0;

    /* all was successful, so put the new list at the tail */
    curlist.splice(curlist.end(), newlist);

    debugs(28, 2, numREs << " REs are optimised into one RE.");
    if (numREs > 100) {
        debugs(28, (opt_parse_cfg_only?DBG_IMPORTANT:2), "" << cfg_filename << " line " << config_lineno << ": " << config_input_line);
        debugs(28, (opt_parse_cfg_only?DBG_IMPORTANT:2), "WARNING: there are more than 100 regular expressions. " <<
               "Consider using less REs or use rules without expressions like 'dstdomain'.");
    }

    return 1;
}

static void
compileUnoptimisedREs(std::list<RegexPattern> &curlist, wordlist * wl)
{
    auto flags = std::regex::extended | std::regex::nosubs;

    while (wl != NULL) {
        if (strcmp(wl->key, "-i") == 0) {
            flags |= std::regex::icase;
        } else if (strcmp(wl->key, "+i") == 0) {
            flags &= ~std::regex::icase;
        } else {
            if (!compileRE(curlist, wl->key , flags))
                debugs(28, DBG_CRITICAL, "ERROR: Skipping regular expression. Compile failed: '" << wl->key << "'");
        }
        wl = wl->next;
    }
}

void
ACLRegexData::parse()
{
    debugs(28, 2, "new Regex line or file");

    wordlist *wl = NULL;
    while (char *t = ConfigParser::RegexStrtokFile()) {
        const char *clean = removeUnnecessaryWildcards(t);
        if (strlen(clean) > BUFSIZ-1) {
            debugs(28, DBG_CRITICAL, "" << cfg_filename << " line " << config_lineno << ": " << config_input_line);
            debugs(28, DBG_CRITICAL, "ERROR: Skipping regular expression. Larger than " << BUFSIZ-1 << " characters: '" << clean << "'");
        } else {
            debugs(28, 3, "buffering RE '" << clean << "'");
            wordlistAdd(&wl, clean);
        }
    }

    if (!compileOptimisedREs(data, wl)) {
        debugs(28, DBG_IMPORTANT, "WARNING: optimisation of regular expressions failed; using fallback method without optimisation");
        compileUnoptimisedREs(data, wl);
    }

    wordlistDestroy(&wl);
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

