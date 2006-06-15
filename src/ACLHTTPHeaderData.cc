/*
 * $Id: ACLHTTPHeaderData.cc,v 1.1 2006/06/14 19:18:24 serassio Exp $
 *
 * DEBUG: section 28    Access Control
 * AUTHOR: Duane Wessels
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
 */

#include "squid.h"
#include "ACLHTTPHeaderData.h"
#include "authenticate.h"
#include "ACLChecklist.h"
#include "ACL.h"
#include "wordlist.h"
#include "ConfigParser.h"

//TODO: These should be unified
static void aclDestroyRegexList(relist * data);
void
aclDestroyRegexList(relist * data)
{
    relist *next = NULL;

    for (; data; data = next) {
        next = data->next;
        regfree(&data->regex);
        safe_free(data->pattern);
        memFree(data, MEM_RELIST);
    }
}

ACLHTTPHeaderData::~ACLHTTPHeaderData()
{
    aclDestroyRegexList(data);
}

bool
ACLHTTPHeaderData::match(HttpHeader* hdr)
{
    if (hdr == NULL)
        return false;

    debug(28, 3) ("aclHeaderData::match: checking '%s'\n", hdrName.buf());

    relist *first, *prev;

    first = data;

    prev = NULL;

    relist *current = first;

    String value = hdrId != HDR_BAD_HDR ? hdr->getStrOrList(hdrId) : hdr->getByName(hdrName.buf());

    // A header value will not be modified, but may not be present
    while (value.buf() && current) {
        debug(28, 3) ("aclHeaderData::match: looking for '%s'\n", current->pattern);

        if (regexec(&current->regex, value.buf(), 0, 0, 0) == 0) {
            if (prev != NULL) {
                /* shift the element just found to the second position
                 * in the list */
                prev->next = current->next;
                current->next = first->next;
                first->next = current;
            }

            debug(28, 2) ("aclHeaderData::match: match '%s' found in '%s'\n",
                          current->pattern, value.buf());
            return 1;
        }

        prev = current;
        current = current->next;
    }

    return 0;
}

wordlist *
ACLHTTPHeaderData::dump()
{
    wordlist *W = NULL;
    relist *temp = data;

    while (temp != NULL) {
        wordlistAdd(&W, temp->pattern);
        temp = temp->next;
    }

    return W;
}

static void aclParseHeaderList(relist **curlist);
//TODO: These should be merged...
void
aclParseHeaderList(relist **curlist)
{
    relist **Tail;
    relist *q = NULL;
    char *t = NULL;
    regex_t comp;
    int errcode;
    int flags = REG_EXTENDED | REG_NOSUB;

    for (Tail = (relist **)curlist; *Tail; Tail = &((*Tail)->next))

        ;

    while ((t = ConfigParser::strtokFile())) {
        if (strcmp(t, "-i") == 0) {
            flags |= REG_ICASE;
            continue;
        }

        if (strcmp(t, "+i") == 0) {
            flags &= ~REG_ICASE;
            continue;
        }

        if ((errcode = regcomp(&comp, t, flags)) != 0) {
            char errbuf[256];
            regerror(errcode, &comp, errbuf, sizeof errbuf);
            debug(28, 0) ("%s line %d: %s\n",
                          cfg_filename, config_lineno, config_input_line);
            debug(28, 0) ("aclParseHeaderList: Invalid regular expression '%s': %s\n",
                          t, errbuf);
            continue;
        }

        q = (relist *)memAllocate(MEM_RELIST);
        q->pattern = xstrdup(t);
        q->regex = comp;
        *(Tail) = q;
        Tail = &q->next;
    }
}

void
ACLHTTPHeaderData::parse()
{
    char* t = strtokFile();
    assert (t != NULL);
    hdrName = t;
    hdrId = httpHeaderIdByNameDef(hdrName.buf(), strlen(hdrName.buf()));
    aclParseHeaderList(&data);
}

bool
ACLHTTPHeaderData::empty() const
{
    return data == NULL;
}

ACLData<HttpHeader*> *
ACLHTTPHeaderData::clone() const
{
    /* Header's don't clone yet. */
    assert (!data);
    return new ACLHTTPHeaderData;
}

