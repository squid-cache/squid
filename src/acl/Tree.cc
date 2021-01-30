/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "acl/Checklist.h"
#include "acl/Tree.h"
#include "wordlist.h"

CBDATA_NAMESPACED_CLASS_INIT(Acl, Tree);

Acl::Answer
Acl::Tree::winningAction() const
{
    return actionAt(lastMatch_ - nodes.begin());
}

Acl::Answer
Acl::Tree::lastAction() const
{
    if (actions.empty())
        return ACCESS_DUNNO;
    return actions.back();
}

/// computes action that corresponds to the position of the matched rule
Acl::Answer
Acl::Tree::actionAt(const Nodes::size_type pos) const
{
    assert(pos < nodes.size());
    if (actions.size()) {
        assert(actions.size() == nodes.size());
        return actions[pos];
    }
    // default for matched rules in trees without actions
    return ACCESS_ALLOWED;
}

void
Acl::Tree::add(ACL *rule, const Acl::Answer &action)
{
    // either all rules have actions or none
    assert(nodes.size() == actions.size());
    InnerNode::add(rule);
    actions.push_back(action);
}

void
Acl::Tree::add(ACL *rule)
{
    // either all rules have actions or none
    assert(actions.empty());
    InnerNode::add(rule);
}

bool
Acl::Tree::bannedAction(ACLChecklist *checklist, Nodes::const_iterator node) const
{
    if (actions.size()) {
        assert(actions.size() == nodes.size());
        const Nodes::size_type pos = node - nodes.begin();
        return checklist->bannedAction(actions.at(pos));
    }
    return false;
}

