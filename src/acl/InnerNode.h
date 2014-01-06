#ifndef SQUID_ACL_INNER_NODE_H
#define SQUID_ACL_INNER_NODE_H

#include "acl/Acl.h"
#include <vector>

namespace Acl
{

typedef std::vector<ACL*> Nodes; ///< a collection of nodes

/// An intermediate ACL tree node. Manages a collection of child tree nodes.
class InnerNode: public ACL
{
public:
    // No ~InnerNode() to delete children. They are aclRegister()ed instead.

    /// Resumes matching (suspended by an async call) at the given position.
    bool resumeMatchingAt(ACLChecklist *checklist, Acl::Nodes::const_iterator pos) const;

    /// the number of children nodes
    Nodes::size_type childrenCount() const { return nodes.size(); }

    /* ACL API */
    virtual void prepareForUse();
    virtual bool empty() const;
    virtual wordlist *dump() const;

    /// parses one "acl name type acl1 acl2..." line, appending to nodes
    void lineParse();

    /// appends the node to the collection and takes control over it
    void add(ACL *node);

protected:
    /// checks whether the nodes match, starting with the given one
    /// kids determine what a match means for their type of intermediate nodes
    virtual int doMatch(ACLChecklist *checklist, Nodes::const_iterator start) const = 0;

    /* ACL API */
    virtual int match(ACLChecklist *checklist);

    // XXX: use refcounting instead of raw pointers
    std::vector<ACL*> nodes; ///< children nodes of this intermediate node
};

} // namespace Acl

#endif /* SQUID_ACL_INNER_NODE_H */
