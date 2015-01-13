/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ACL_TREE_H
#define SQUID_ACL_TREE_H

#include "acl/BoolOps.h"
#include "SBufList.h"

namespace Acl
{

/// An ORed set of rules at the top of the ACL expression tree, providing two
/// unique properties: cbdata protection and optional rule actions.
class Tree: public OrNode
{
public:
    /// dumps <name, action, rule, new line> tuples
    /// action.kind is mapped to a string using the supplied conversion table
    typedef const char **ActionToString;
    SBufList treeDump(const char *name, const ActionToString &convert) const;

    /// Returns the corresponding action after a successful tree match.
    allow_t winningAction() const;

    /// what action to use if no nodes matched
    allow_t lastAction() const;

    /// appends and takes control over the rule with a given action
    void add(ACL *rule, const allow_t &action);
    void add(ACL *rule); ///< same as InnerNode::add()

protected:
    allow_t actionAt(const Nodes::size_type pos) const;

    /// if not empty, contains actions corresponding to InnerNode::nodes
    typedef std::vector<allow_t> Actions;
    Actions actions;

private:
    // XXX: We should use refcounting instead, but it requires making ACLs
    // refcounted as well. Otherwise, async lookups will reach deleted ACLs.
    CBDATA_CLASS2(Tree);
};

} // namespace Acl

#endif /* SQUID_ACL_TREE_H */

