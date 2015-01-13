/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 28    Access Control */

#include "squid.h"
#include "acl/FilledChecklist.h"
#include "acl/HttpStatus.h"
#include "cache_cf.h"
#include "Debug.h"
#include "HttpReply.h"

#include <climits>

static void aclParseHTTPStatusList(SplayNode<acl_httpstatus_data *> **curlist);
static int aclHTTPStatusCompare(acl_httpstatus_data * const &a, acl_httpstatus_data * const &b);
static int aclMatchHTTPStatus(SplayNode<acl_httpstatus_data*> **dataptr, Http::StatusCode status);

acl_httpstatus_data::acl_httpstatus_data(int x) : status1(x), status2(x) { ; }

acl_httpstatus_data::acl_httpstatus_data(int x, int y) : status1(x), status2(y) { ; }

SBuf
acl_httpstatus_data::toStr() const
{
    SBuf rv;
    if (status2 == INT_MAX)
        rv.Printf("%d-", status1);
    else if (status1 == status2)
        rv.Printf("%d", status1);
    else
        rv.Printf("%d-%d", status1, status2);
    return rv;
}

int acl_httpstatus_data::compare(acl_httpstatus_data* const& a, acl_httpstatus_data* const& b)
{
    int ret;
    ret = aclHTTPStatusCompare(b, a);

    if (ret != 0)
        ret = aclHTTPStatusCompare(a, b);

    if (ret == 0) {
        const SBuf sa = a->toStr();
        const SBuf sb = b->toStr();
        debugs(28, DBG_CRITICAL, "WARNING: '" << sa << "' is a subrange of '" << sb << "'");
        debugs(28, DBG_CRITICAL, "WARNING: because of this '" << sa << "' is ignored to keep splay tree searching predictable");
        debugs(28, DBG_CRITICAL, "WARNING: You should probably remove '" << sb << "' from the ACL named '" << AclMatchedName << "'");
    }

    return ret;
}

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
    return aclMatchHTTPStatus(&data, Filled(checklist)->reply->sline.status());
}

int
aclMatchHTTPStatus(SplayNode<acl_httpstatus_data*> **dataptr, const Http::StatusCode status)
{

    acl_httpstatus_data X(status);
    SplayNode<acl_httpstatus_data*> **Top = dataptr;
    *Top = Top[0]->splay(&X, aclHTTPStatusCompare);

    debugs(28, 3, "aclMatchHTTPStatus: '" << status << "' " << (splayLastResult ? "NOT found" : "found"));
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
    // state is a SBufList*
    static_cast<SBufList *>(state)->push_back(node->toStr());
}

SBufList
ACLHTTPStatus::dump() const
{
    SBufList w;
    data->walk(aclDumpHTTPStatusListWalkee, &w);
    return w;
}

