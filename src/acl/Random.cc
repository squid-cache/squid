/*
 * DEBUG: section 28    Access Control
 * AUTHOR: Amos Jeffries
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

#include "acl/FilledChecklist.h"
#include "acl/Random.h"
#include "cache_cf.h"
#include "Debug.h"
#include "Parsing.h"
#include "wordlist.h"

ACL *
ACLRandom::clone() const
{
    return new ACLRandom(*this);
}

ACLRandom::ACLRandom(char const *theClass) : data(0.0), class_(theClass)
{
    memset(pattern, 0 , sizeof(pattern));
}

ACLRandom::ACLRandom(ACLRandom const & old) : data(old.data), class_(old.class_)
{
    memcpy(pattern, old.pattern, sizeof(pattern));
}

ACLRandom::~ACLRandom()
{ }

char const *
ACLRandom::typeString() const
{
    return class_;
}

bool
ACLRandom::empty () const
{
    return data == 0.0;
}

bool
ACLRandom::valid() const
{
    return !empty();
}

/*******************/
/* aclParseRandomList */
/*******************/
void
ACLRandom::parse()
{
    char *t;
    char bufa[256], bufb[256];

    t = strtokFile();
    if (!t) {
        debugs(28, DBG_PARSE_NOTE(DBG_IMPORTANT), "ACL random missing pattern");
        return;
    }

    debugs(28, 5, "aclParseRandomData: " << t);

    // seed random generator ...
    srand(time(NULL));

    if (sscanf(t, "%[0-9]:%[0-9]", bufa, bufb) == 2) {
        int a = xatoi(bufa);
        int b = xatoi(bufb);
        if (a <= 0 || b <= 0) {
            debugs(28, DBG_CRITICAL, "ERROR: ACL random with bad pattern: '" << t << "'");
            return;
        } else
            data = a / (double)(a+b);
    } else if (sscanf(t, "%[0-9]/%[0-9]", bufa, bufb) == 2) {
        int a = xatoi(bufa);
        int b = xatoi(bufb);
        if (a <= 0 || b <= 0) {
            debugs(28, DBG_CRITICAL, "ERROR: ACL random with bad pattern: '" << t << "'");
            return;
        } else
            data = (double) a / (double) b;
    } else if (sscanf(t, "0.%[0-9]", bufa) == 1) {
        data = atof(t);
    } else {
        debugs(28, DBG_CRITICAL, "ERROR: ACL random with bad pattern: '" << t << "'");
        return;
    }

    // save the exact input pattern. so we can display it later.
    memcpy(pattern, t, min(sizeof(pattern)-1,strlen(t)));
}

int
ACLRandom::match(ACLChecklist *cl)
{
    // make up the random value
    double random = ((double)rand() / (double)RAND_MAX);

    debugs(28, 3, "ACL Random: " << name << " " << pattern << " test: " << data << " > " << random << " = " << ((data > random)?"MATCH":"NO MATCH") );
    return (data > random)?1:0;
}

wordlist *
ACLRandom::dump() const
{
    wordlist *w = NULL;
    wordlistAdd(&w, pattern);
    return w;
}
