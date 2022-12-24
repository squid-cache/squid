/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ACL_TREE_H
#define SQUID_ACL_TREE_H

#include "acl/BoolOps.h"
#include "sbuf/List.h"

namespace Acl
{

/// An ORed set of rules at the top of the ACL expression tree, providing two
/// unique properties: cbdata protection and optional rule actions.
class Tree: public OrNode
{
    // XXX: We should use refcounting instead, but it requires making ACLs
    // refcounted as well. Otherwise, async lookups will reach deleted ACLs.
    CBDATA_CLASS(Tree);

public:
    /// dumps <name, action, rule, new line> tuples
    /// the supplied converter maps action.kind to a string
    template <class ActionToStringConverter>
    SBufList treeDump(const char *name, ActionToStringConverter converter) const;

    /// Returns the corresponding action after a successful tree match.
    Answer winningAction() const;

    /// what action to use if no nodes matched
    Answer lastAction() const;

    /// appends and takes control over the rule with a given action
    void add(ACL *rule, const Answer &action);
    void add(ACL *rule); ///< same as InnerNode::add()

protected:
    /// Acl::OrNode API
    virtual bool bannedAction(ACLChecklist *, Nodes::const_iterator) const override;
    Answer actionAt(const Nodes::size_type pos) const;

    /// if not empty, contains actions corresponding to InnerNode::nodes
    typedef std::vector<Answer> Actions;
    Actions actions;
};

inline const char *
AllowOrDeny(const Answer &action)
{
    return action.allowed() ? "allow" : "deny";
}

template <class ActionToStringConverter>
inline SBufList
Tree::treeDump(const char *prefix, ActionToStringConverter converter) const
{
    SBufList text;
    Actions::const_iterator action = actions.begin();
    typedef Nodes::const_iterator NCI;
    for (NCI node = nodes.begin(); node != nodes.end(); ++node) {

        text.push_back(SBuf(prefix));

        if (action != actions.end()) {
            static const SBuf DefaultActString("???");
            const char *act = converter(*action);
            text.push_back(act ? SBuf(act) : DefaultActString);
            ++action;
        }

        text.splice(text.end(), (*node)->dump());
        text.push_back(SBuf("\n"));
    }
    return text;
}

} // namespace Acl

#endif /* SQUID_ACL_TREE_H */

