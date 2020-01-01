/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "acl/BoolOps.h"
#include "acl/Checklist.h"
#include "Debug.h"
#include "sbuf/SBuf.h"

/* Acl::NotNode */

Acl::NotNode::NotNode(ACL *acl)
{
    assert(acl);
    Must(strlen(acl->name) <= sizeof(name)-2);
    name[0] = '!';
    name[1] = '\0';
    xstrncpy(&name[1], acl->name, sizeof(name)-1); // -1 for '!'
    add(acl);
}

void
Acl::NotNode::parse()
{
    // Not implemented: by the time an upper level parser discovers
    // an '!' operator, there is nothing left for us to parse.
    assert(false);
}

int
Acl::NotNode::doMatch(ACLChecklist *checklist, Nodes::const_iterator start) const
{
    assert(start == nodes.begin()); // we only have one node

    if (checklist->matchChild(this, start, *start))
        return 0; // converting match into mismatch

    if (!checklist->keepMatching())
        return -1; // suspend on async calls and stop on failures

    return 1; // converting mismatch into match
}

char const *
Acl::NotNode::typeString() const
{
    return "!";
}

ACL *
Acl::NotNode::clone() const
{
    // Not implemented: we are not a named ACL type in squid.conf so nobody
    // should try to create a NotNode instance by ACL type name (which is
    // what clone() API is for -- it does not really clone anything).
    assert(false);
    return NULL;
}

SBufList
Acl::NotNode::dump() const
{
    SBufList text;
    text.push_back(SBuf(name));
    return text;
}

/* Acl::AndNode */

char const *
Acl::AndNode::typeString() const
{
    return "and";
}

ACL *
Acl::AndNode::clone() const
{
    return new AndNode;
}

int
Acl::AndNode::doMatch(ACLChecklist *checklist, Nodes::const_iterator start) const
{
    // find the first node that does not match
    for (Nodes::const_iterator i = start; i != nodes.end(); ++i) {
        if (!checklist->matchChild(this, i, *i))
            return checklist->keepMatching() ? 0 : -1;
    }

    // one and not zero on empty because in math empty product equals identity
    return 1; // no mismatches found (i.e., all kids matched)
}

void
Acl::AndNode::parse()
{
    // Not implemented: AndNode cannot be configured directly. See Acl::AllOf.
    assert(false);
}

/* Acl::OrNode */

char const *
Acl::OrNode::typeString() const
{
    return "any-of";
}

ACL *
Acl::OrNode::clone() const
{
    return new OrNode;
}

bool
Acl::OrNode::bannedAction(ACLChecklist *, Nodes::const_iterator) const
{
    return false;
}

int
Acl::OrNode::doMatch(ACLChecklist *checklist, Nodes::const_iterator start) const
{
    lastMatch_ = nodes.end();

    // find the first node that matches, but stop if things go wrong
    for (Nodes::const_iterator i = start; i != nodes.end(); ++i) {
        if (bannedAction(checklist, i))
            continue;
        if (checklist->matchChild(this, i, *i)) {
            lastMatch_ = i;
            return 1;
        }

        if (!checklist->keepMatching())
            return -1; // suspend on async calls and stop on failures
    }

    // zero and not one on empty because in math empty sum equals zero
    return 0; // all nodes mismatched
}

void
Acl::OrNode::parse()
{
    // Not implemented: OrNode cannot be configured directly. See Acl::AnyOf.
    assert(false);
}

