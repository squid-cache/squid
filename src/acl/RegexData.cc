/*
 * DEBUG: section 28    Access Control
 * AUTHOR: Duane Wessels
 * AUTHOR: Marcus Kool
 *
 * SQUID Web Proxy Cache          http://www.squid-cache.org/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from
 *  the Internet community; see the CONTRIBUTORS file for full
 *  details.   Many organizations have provided support for Squid's
 *  development; see the SPONSORS file for full details.  Squid is
 *  Copyrighted (C) 2001 by the Regents of the University of
 *  California; see the COPYRIGHT file for full details.  Squid
 *  incorporates software developed and/or copyrighted by other
 *  sources; see the CREDITS file for full details.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111, USA.
 *
 *
 * Copyright (c) 2003, Robert Collins <robertc@squid-cache.org>
 * Copyright (c) 2011, Marcus Kool
 */

#include "squid.h"
#include "acl/RegexData.h"
#include "acl/Checklist.h"
#include "acl/Acl.h"
#include "ConfigParser.h"
#include "Debug.h"
#include "Mem.h"
#include "RegexList.h"
#include "wordlist.h"

static void
aclDestroyRegexList(RegexList * data)
{
    RegexList *next = NULL;

    for (; data; data = next) {
        next = data->next;
        regfree(&data->regex);
        safe_free(data->pattern);
        memFree(data, MEM_RELIST);
    }
}

ACLRegexData::~ACLRegexData()
{
    aclDestroyRegexList(data);
}

bool
ACLRegexData::match(char const *word)
{
    if (word == NULL)
        return 0;

    debugs(28, 3, "aclRegexData::match: checking '" << word << "'");

    RegexList *first, *prev;

    first = data;

    prev = NULL;

    RegexList *current = first;

    while (current) {
        debugs(28, 3, "aclRegexData::match: looking for '" << current->pattern << "'");

        if (regexec(&current->regex, word, 0, 0, 0) == 0) {
            if (prev != NULL) {
                /* shift the element just found to the second position
                 * in the list */
                prev->next = current->next;
                current->next = first->next;
                first->next = current;
            }

            debugs(28, 2, "aclRegexData::match: match '" << current->pattern << "' found in '" << word << "'");
            return 1;
        }

        prev = current;
        current = current->next;
    }

    return 0;
}

wordlist *
ACLRegexData::dump()
{
    wordlist *W = NULL;
    RegexList *temp = data;
    int flags = REG_EXTENDED | REG_NOSUB;

    while (temp != NULL) {
        if (temp->flags != flags) {
            if ((temp->flags&REG_ICASE) != 0) {
                wordlistAdd(&W, "-i");
            } else {
                wordlistAdd(&W, "+i");
            }
            flags = temp->flags;
        }

        wordlistAdd(&W, temp->pattern);
        temp = temp->next;
    }

    return W;
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

static RegexList **
compileRE(RegexList **Tail, char * RE, int flags)
{
    int errcode;
    RegexList *q;
    regex_t comp;

    if (RE == NULL  ||  *RE == '\0')
        return Tail;

    if ((errcode = regcomp(&comp, RE, flags)) != 0) {
        char errbuf[256];
        regerror(errcode, &comp, errbuf, sizeof errbuf);
        debugs(28, DBG_CRITICAL, "" << cfg_filename << " line " << config_lineno << ": " << config_input_line);
        debugs(28, DBG_CRITICAL, "ERROR: invalid regular expression: '" << RE << "': " << errbuf);
        return NULL;
    }
    debugs(28, 2, "compileRE: compiled '" << RE << "' with flags " << flags );

    q = (RegexList *) memAllocate(MEM_RELIST);
    q->pattern = xstrdup(RE);
    q->regex = comp;
    q->flags = flags;
    *(Tail) = q;
    Tail = &q->next;

    return Tail;
}

/** Compose and compile one large RE from a set of (small) REs.
 * The ultimate goal is to have only one RE per ACL so that regexec() is
 * called only once per ACL.
 */
static int
compileOptimisedREs(RegexList **curlist, wordlist * wl)
{
    RegexList **Tail;
    RegexList *newlist;
    RegexList **newlistp;
    int numREs = 0;
    int flags = REG_EXTENDED | REG_NOSUB;
    int largeREindex = 0;
    char largeRE[BUFSIZ];

    newlist = NULL;
    newlistp = &newlist;

    largeRE[0] = '\0';

    while (wl != NULL) {
        int RElen;
        RElen = strlen( wl->key );

        if (strcmp(wl->key, "-i") == 0) {
            if (flags & REG_ICASE) {
                /* optimisation of  -i ... -i */
                debugs(28, 2, "compileOptimisedREs: optimisation of -i ... -i" );
            } else {
                debugs(28, 2, "compileOptimisedREs: -i" );
                newlistp = compileRE( newlistp, largeRE, flags );
                if (newlistp == NULL) {
                    aclDestroyRegexList( newlist );
                    return 0;
                }
                flags |= REG_ICASE;
                largeRE[largeREindex=0] = '\0';
            }
        } else if (strcmp(wl->key, "+i") == 0) {
            if ((flags & REG_ICASE) == 0) {
                /* optimisation of  +i ... +i */
                debugs(28, 2, "compileOptimisedREs: optimisation of +i ... +i");
            } else {
                debugs(28, 2, "compileOptimisedREs: +i");
                newlistp = compileRE( newlistp, largeRE, flags );
                if (newlistp == NULL) {
                    aclDestroyRegexList( newlist );
                    return 0;
                }
                flags &= ~REG_ICASE;
                largeRE[largeREindex=0] = '\0';
            }
        } else if (RElen + largeREindex + 3 < BUFSIZ-1) {
            debugs(28, 2, "compileOptimisedREs: adding RE '" << wl->key << "'");
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
            debugs(28, 2, "compileOptimisedREs: buffer full, generating new optimised RE..." );
            newlistp = compileRE( newlistp, largeRE, flags );
            if (newlistp == NULL) {
                aclDestroyRegexList( newlist );
                return 0;
            }
            largeRE[largeREindex=0] = '\0';
            continue;    /* do the loop again to add the RE to largeRE */
        }
        wl = wl->next;
    }

    newlistp = compileRE( newlistp, largeRE, flags );
    if (newlistp == NULL) {
        aclDestroyRegexList( newlist );
        return 0;
    }

    /* all was successful, so put the new list at the tail */
    if (*curlist == NULL) {
        *curlist = newlist;
    } else {
        for (Tail = curlist; *Tail != NULL; Tail = &((*Tail)->next))
            ;
        (*Tail) = newlist;
    }

    debugs(28, 2, "compileOptimisedREs: " << numREs << " REs are optimised into one RE.");
    if (numREs > 100) {
        debugs(28, (opt_parse_cfg_only?DBG_IMPORTANT:2), "" << cfg_filename << " line " << config_lineno << ": " << config_input_line);
        debugs(28, (opt_parse_cfg_only?DBG_IMPORTANT:2), "WARNING: there are more than 100 regular expressions. " <<
               "Consider using less REs or use rules without expressions like 'dstdomain'.");
    }

    return 1;
}

static void
compileUnoptimisedREs(RegexList **curlist, wordlist * wl)
{
    RegexList **Tail;
    RegexList **newTail;
    int flags = REG_EXTENDED | REG_NOSUB;

    for (Tail = curlist; *Tail != NULL; Tail = &((*Tail)->next))
        ;

    while (wl != NULL) {
        if (strcmp(wl->key, "-i") == 0) {
            flags |= REG_ICASE;
        } else if (strcmp(wl->key, "+i") == 0) {
            flags &= ~REG_ICASE;
        } else {
            newTail = compileRE( Tail, wl->key , flags );
            if (newTail == NULL)
                debugs(28, DBG_CRITICAL, "ERROR: Skipping regular expression. Compile failed: '" << wl->key << "'");
            else
                Tail = newTail;
        }
        wl = wl->next;
    }
}

static void
aclParseRegexList(RegexList **curlist)
{
    char *t;
    wordlist *wl = NULL;

    debugs(28, 2, HERE << "aclParseRegexList: new Regex line or file");

    while ((t = ConfigParser::strtokFile()) != NULL) {
        const char *clean = removeUnnecessaryWildcards(t);
        if (strlen(clean) > BUFSIZ-1) {
            debugs(28, DBG_CRITICAL, "" << cfg_filename << " line " << config_lineno << ": " << config_input_line);
            debugs(28, DBG_CRITICAL, "ERROR: Skipping regular expression. Larger than " << BUFSIZ-1 << " characters: '" << clean << "'");
        } else {
            debugs(28, 3, "aclParseRegexList: buffering RE '" << clean << "'");
            wordlistAdd(&wl, clean);
        }
    }

    if (!compileOptimisedREs(curlist, wl)) {
        debugs(28, DBG_IMPORTANT, "WARNING: optimisation of regular expressions failed; using fallback method without optimisation");
        compileUnoptimisedREs(curlist, wl);
    }

    wordlistDestroy(&wl);
}

void
ACLRegexData::parse()
{
    aclParseRegexList(&data);
}

bool
ACLRegexData::empty() const
{
    return data == NULL;
}

ACLData<char const *> *
ACLRegexData::clone() const
{
    /* Regex's don't clone yet. */
    assert (!data);
    return new ACLRegexData;
}
