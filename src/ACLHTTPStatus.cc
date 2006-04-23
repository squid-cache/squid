/*
 * $Id: ACLHTTPStatus.cc,v 1.2 2006/04/23 11:10:31 robertc Exp $
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

#include "config.h"
#ifdef _SQUID_CYGWIN_
#include <squid_windows.h>
#endif
#include "squid.h"

#include "ACLHTTPStatus.h"
#include "HttpReply.h"
#include "wordlist.h"

static void aclParseHTTPStatusList(SplayNode<acl_httpstatus_data *> **curlist);
static int aclHTTPStatusCompare(acl_httpstatus_data * const &a, acl_httpstatus_data * const &b);
static int aclMatchHTTPStatus(SplayNode<acl_httpstatus_data*> **dataptr, http_status status);

acl_httpstatus_data::acl_httpstatus_data(int x) : status1(x), status2(x) { ; }

acl_httpstatus_data::acl_httpstatus_data(int x, int y) : status1(x), status2(y) { ; }

void acl_httpstatus_data::toStr(char* buf, int len) const
{
    if (status2 == INT_MAX)
        snprintf(buf, len, "%d-", status1);
    else if (status1 == status2)
        snprintf(buf, len, "%d", status1);
    else
        snprintf(buf, len, "%d-%d", status1, status2);
}

int acl_httpstatus_data::compare(acl_httpstatus_data* const& a, acl_httpstatus_data* const& b)
{
    int ret;
    ret = aclHTTPStatusCompare(b, a);

    if (ret != 0)
        ret = aclHTTPStatusCompare(a, b);

    if (ret == 0) {
        char bufa[8];
        char bufb[8];
        a->toStr(bufa, sizeof(bufa));
        b->toStr(bufb, sizeof(bufb));
        debug(28, 0) ("WARNING: '%s' is a subrange of '%s'\n", bufa, bufb);
        debug(28, 0) ("WARNING: because of this '%s' is ignored "
                      "to keep splay tree searching predictable\n", bufa);
        debug(28, 0) ("WARNING: You should probably remove '%s' "
                      "from the ACL named '%s'\n", bufb, AclMatchedName);
    }

    return ret;
}

ACL::Prototype ACLHTTPStatus::RegistryProtoype(&ACLHTTPStatus::RegistryEntry_, "http_status");

ACLHTTPStatus ACLHTTPStatus::RegistryEntry_("http_status");

ACL *
ACLHTTPStatus::clone() const
{
    return new ACLHTTPStatus(*this);
}

ACLHTTPStatus::ACLHTTPStatus (char const *theClass) : data(NULL), class_ (theClass)
{}

ACLHTTPStatus::ACLHTTPStatus (ACLHTTPStatus const & old) : data(NULL), class_ (old.class_)
{
    /* we don't have copy constructors for the data yet */
    assert(!old.data);
}

ACLHTTPStatus::~ACLHTTPStatus()
{
    if (data)
        data->destroy(SplayNode<acl_httpstatus_data*>::DefaultFree);
}

char const *
ACLHTTPStatus::typeString() const
{
    return class_;
}

bool
ACLHTTPStatus::empty () const
{
    return data->empty();
}

acl_httpstatus_data*
aclParseHTTPStatusData(const char *t)
{
    int status;
    status = atoi(t);
    t = strchr(t, '-');

    if (!t)
        return new acl_httpstatus_data(status);

    if (*(++t))
        return new acl_httpstatus_data(status, atoi(t));

    return new acl_httpstatus_data(status, INT_MAX);
}


void
ACLHTTPStatus::parse()
{
    aclParseHTTPStatusList (&data);
}

void
aclParseHTTPStatusList(SplayNode<acl_httpstatus_data *> **curlist)
{
    char *t = NULL;
    SplayNode<acl_httpstatus_data*> **Top = curlist;
    acl_httpstatus_data *q = NULL;

    while ((t = strtokFile())) {
        if ((q = aclParseHTTPStatusData(t)) == NULL)
            continue;

        *Top = (*Top)->insert(q, acl_httpstatus_data::compare);
    }
}

int
ACLHTTPStatus::match(ACLChecklist *checklist)
{
    return aclMatchHTTPStatus(&data, checklist->reply->sline.status);
}

int
aclMatchHTTPStatus(SplayNode<acl_httpstatus_data*> **dataptr, http_status status)
{

    acl_httpstatus_data X(status);
    SplayNode<acl_httpstatus_data*> **Top = dataptr;
    *Top = Top[0]->splay(&X, aclHTTPStatusCompare);

    debug(28, 3) ("aclMatchHTTPStatus: '%d' %s\n", status,
                  splayLastResult ? "NOT found" : "found");
    return (0 == splayLastResult);
}

static int
aclHTTPStatusCompare(acl_httpstatus_data * const &a, acl_httpstatus_data * const &b)
{
    if (a->status1 < b->status1)
        return 1;

    if (a->status1 > b->status2)
        return -1;

    return 0;
}

static void
aclDumpHTTPStatusListWalkee(acl_httpstatus_data * const &node, void *state)
{
    static char buf[8];
    node->toStr(buf, sizeof(buf));
    wordlistAdd((wordlist **)state, buf);
}

wordlist *
ACLHTTPStatus::dump() const
{
    wordlist *w = NULL;
    data->walk(aclDumpHTTPStatusListWalkee, &w);
    return w;
}

