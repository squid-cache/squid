/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 28    Access Control */

#include "squid.h"
#include "acl/FilledChecklist.h"
#include "acl/HttpStatus.h"
#include "debug/Stream.h"
#include "HttpReply.h"

#include <algorithm>
#include <climits>
#include <iostream>

static void aclParseHTTPStatusList(Splay<acl_httpstatus_data *> **curlist);
static int aclHTTPStatusCompare(acl_httpstatus_data * const &a, acl_httpstatus_data * const &b);
static int aclMatchHTTPStatus(Splay<acl_httpstatus_data*> **dataptr, Http::StatusCode status);

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

ACLHTTPStatus::ACLHTTPStatus (char const *theClass) : data(nullptr), class_ (theClass)
{}

ACLHTTPStatus::~ACLHTTPStatus()
{
    if (data) {
        data->destroy();
        delete data;
    }
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

static acl_httpstatus_data*
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
    if (!data)
        data = new Splay<acl_httpstatus_data*>();

    aclParseHTTPStatusList (&data);
}

static std::ostream &
operator <<(std::ostream &os, const acl_httpstatus_data &status)
{
    os << status.toStr();
    return os;
}

template <typename Item, typename SplayT>
static void
aclInsertWithoutOverlaps(SplayT &container, Item *newItem, typename SplayT::SPLAYCMP comparator)
{
    while (const auto oldItemPointer = container.insert(newItem, comparator)) {
        const auto oldItem = *oldItemPointer;
        assert(oldItem);

        if (oldItem->contains(*newItem)) {
            debugs(28, DBG_PARSE_NOTE(DBG_IMPORTANT), "WARNING: Ignoring " << *newItem << " because it is already covered by " << *oldItem <<
                   Debug::Extra << "advice: Remove value " << *newItem << " from the ACL named " << AclMatchedName);
            delete newItem;
            return;
        }

        if (newItem->contains(*oldItem)) {
            debugs(28, DBG_PARSE_NOTE(DBG_IMPORTANT), "WARNING: Ignoring " << *oldItem << " because it is covered by " << *newItem <<
                   Debug::Extra << "advice: Remove value " << *oldItem << " from the ACL named " << AclMatchedName);
            container.remove(oldItem, comparator);
            delete oldItem;
            continue; // still need to insert newItem (and it may conflict with other old items)
        }

        const auto minLeft = std::min(oldItem->status1, newItem->status1);
        const auto maxRight = std::max(oldItem->status2, newItem->status2);
        const auto combinedItem = new acl_httpstatus_data(minLeft, maxRight);
        debugs(28, DBG_PARSE_NOTE(DBG_IMPORTANT), "WARNING: Merging overlapping " << *newItem << " and " << *oldItem << " into " << *combinedItem <<
               Debug::Extra << "advice: Replace values " << *newItem << " and " << *oldItem << " with " << *combinedItem << " in the ACL named " << AclMatchedName);
        delete newItem;
        newItem = combinedItem;
        container.remove(oldItem, comparator);
        delete oldItem;
        continue; // still need to insert updated newItem (and it may conflict with other old items)
    }
}

void
aclParseHTTPStatusList(Splay<acl_httpstatus_data *> **curlist)
{
    while (char *t = ConfigParser::strtokFile()) {
        if (acl_httpstatus_data *q = aclParseHTTPStatusData(t))
            aclInsertWithoutOverlaps(**curlist, q, aclHTTPStatusCompare);
    }
}

int
ACLHTTPStatus::match(ACLChecklist *checklist)
{
    return aclMatchHTTPStatus(&data, Filled(checklist)->reply->sline.status());
}

int
aclMatchHTTPStatus(Splay<acl_httpstatus_data*> **dataptr, const Http::StatusCode status)
{
    acl_httpstatus_data X(status);
    const acl_httpstatus_data * const * result = (*dataptr)->find(&X, aclHTTPStatusCompare);

    debugs(28, 3, "aclMatchHTTPStatus: '" << status << "' " << (result ? "found" : "NOT found"));
    return (result != nullptr);
}

static int
aclHTTPStatusCompare(acl_httpstatus_data * const &a, acl_httpstatus_data * const &b)
{
    if (a->status2 < b->status1)
        return 1; // the entire range a is to the left of range b

    if (a->status1 > b->status2)
        return -1; // the entire range a is to the right of range b

    return 0; // equal or partially overlapping ranges
}

struct HttpStatusAclDumpVisitor {
    SBufList contents;
    void operator() (const acl_httpstatus_data * node) {
        contents.push_back(node->toStr());
    }
};

SBufList
ACLHTTPStatus::dump() const
{
    HttpStatusAclDumpVisitor visitor;
    data->visit(visitor);
    return visitor.contents;
}

