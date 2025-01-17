/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_ACL_INNERNODE_H
#define SQUID_SRC_ACL_INNERNODE_H

#include "acl/Node.h"
#include <vector>

namespace Acl
{

/// operands of a boolean ACL expression, in configuration/evaluation order
using Nodes = std::vector<Node::Pointer>;

/// An intermediate Acl::Node tree node. Manages a collection of child tree nodes.
class InnerNode: public Acl::Node
{
public:
    /// Resumes matching (suspended by an async call) at the given position.
    bool resumeMatchingAt(ACLChecklist *checklist, Acl::Nodes::const_iterator pos) const;

    /// the number of children nodes
    Nodes::size_type childrenCount() const { return nodes.size(); }

    /* Acl::Node API */
    void prepareForUse() override;
    bool empty() const override;
    SBufList dump() const override;

    /// parses a [ [!]acl1 [!]acl2... ] sequence, appending to nodes
    /// \returns the number of parsed ACL names
    size_t lineParse();

    /// appends the node to the collection and takes control over it
    void add(Acl::Node *node);

protected:
    /// checks whether the nodes match, starting with the given one
    /// kids determine what a match means for their type of intermediate nodes
    virtual int doMatch(ACLChecklist *checklist, Nodes::const_iterator start) const = 0;

    /* Acl::Node API */
    int match(ACLChecklist *checklist) override;

    Nodes nodes; ///< children of this intermediate node
};

} // namespace Acl

#endif /* SQUID_SRC_ACL_INNERNODE_H */

