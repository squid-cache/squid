/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ACL_LOGIC_H
#define SQUID_ACL_LOGIC_H

#include "acl/InnerNode.h"

/* ACLs defined here are used internally to construct an ACL expression tree.
 * They cannot be specified directly in squid.conf because squid.conf ACLs are
 * more complex than (and are implemented using) these operator-like classes.*/

namespace Acl
{

/// Implements the "not" or "!" operator.
class NotNode: public InnerNode
{
    MEMPROXY_CLASS(NotNode);

public:
    explicit NotNode(ACL *acl);

private:
    /* ACL API */
    virtual char const *typeString() const;
    virtual ACL *clone() const;
    virtual void parse();
    virtual SBufList dump() const;

    /* Acl::InnerNode API */
    virtual int doMatch(ACLChecklist *checklist, Nodes::const_iterator start) const;
};

/// An inner ACL expression tree node representing a boolean conjuction (AND)
/// operator applied to a list of child tree nodes.
/// For example, conditions expressed on a single http_access line are ANDed.
class AndNode: public InnerNode
{
    MEMPROXY_CLASS(AndNode);

public:
    /* ACL API */
    virtual char const *typeString() const;
    virtual ACL *clone() const;
    virtual void parse();

private:
    virtual int doMatch(ACLChecklist *checklist, Nodes::const_iterator start) const;
};

/// An inner ACL expression tree node representing a boolean disjuction (OR)
/// operator applied to a list of child tree nodes.
/// For example, conditions expressed by multiple http_access lines are ORed.
class OrNode: public InnerNode
{
    MEMPROXY_CLASS(OrNode);

public:
    /// whether the given rule should be excluded from matching tests based
    /// on its action
    virtual bool bannedAction(ACLChecklist *, Nodes::const_iterator) const;

    /* ACL API */
    virtual char const *typeString() const;
    virtual ACL *clone() const;
    virtual void parse();

protected:
    mutable Nodes::const_iterator lastMatch_;

private:
    virtual int doMatch(ACLChecklist *checklist, Nodes::const_iterator start) const;
};

} // namespace Acl

#endif /* SQUID_ACL_LOGIC_H */

