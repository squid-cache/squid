/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
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

allow_t
Acl::Tree::winningAction() const
{
    return actionAt(lastMatch_ - nodes.begin());
}

allow_t
Acl::Tree::lastAction() const
{
    if (actions.empty())
        return ACCESS_DUNNO;
    return actions.back();
}

/// computes action that corresponds to the position of the matched rule
allow_t
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
Acl::Tree::add(ACL *rule, const allow_t &action)
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

SBufList
Acl::Tree::treeDump(const char *prefix, const ActionToString &convert) const
{
    SBufList text;
    Actions::const_iterator action = actions.begin();
    typedef Nodes::const_iterator NCI;
    for (NCI node = nodes.begin(); node != nodes.end(); ++node) {

        text.push_back(SBuf(prefix));

        if (action != actions.end()) {
            const char *act = convert ? convert[action->kind] :
                              (*action == ACCESS_ALLOWED ? "allow" : "deny");
            text.push_back(act?SBuf(act):SBuf("???"));
            ++action;
        }

        // temp is needed until c++11 move constructor
        SBufList temp = (*node)->dump();
        text.splice(text.end(), temp);
        text.push_back(SBuf("\n"));
    }
    return text;
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

