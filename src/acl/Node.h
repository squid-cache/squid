/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_ACL_NODE_H
#define SQUID_SRC_ACL_NODE_H

#include "acl/forward.h"
#include "acl/Options.h"
#include "dlink.h"
#include "sbuf/SBuf.h"

class ConfigParser;

namespace Acl {

/// A configurable condition. A node in the ACL expression tree.
/// Can evaluate itself in FilledChecklist context.
/// Does not change during evaluation.
/// \ingroup ACLAPI
class Node: public RefCountable
{

public:
    using Pointer = RefCount<Node>;

    void *operator new(size_t);
    void operator delete(void *);

    /// parses acl directive parts that follow directive name (i.e. "acl")
    static void ParseNamedAcl(ConfigParser &, NamedAcls *&);

    static void Initialize();

    /// A configured ACL with a given name or nil.
    static Acl::Node *FindByName(const SBuf &);

    Node();
    Node(Node &&) = delete;  // no copying of any kind
    virtual ~Node();

    /// sets user-specified ACL name and squid.conf context
    void context(const SBuf &aName, const char *configuration);

    /// Orchestrates matching checklist against the Acl::Node using match(),
    /// after checking preconditions and while providing debugging.
    /// \return true if and only if there was a successful match.
    /// Updates the checklist state on match, async, and failure.
    bool matches(ACLChecklist *checklist) const;

    /// configures Acl::Node options, throwing on configuration errors
    void parseFlags();

    /// parses node representation in squid.conf; dies on failures
    virtual void parse() = 0;
    virtual char const *typeString() const = 0;
    virtual bool isProxyAuth() const;
    virtual SBufList dump() const = 0;
    virtual bool empty() const = 0;
    virtual bool valid() const;

    int cacheMatchAcl(dlink_list *cache, ACLChecklist *);
    virtual int matchForCache(ACLChecklist *checklist);

    virtual void prepareForUse() {}

    // TODO: Find a way to make options() and this method constant
    /// Prints aggregated "acl" (or similar) directive configuration, including
    /// the given directive name, ACL name, ACL type, and ACL parameters. The
    /// printed parameters are collected from all same-name "acl" directives.
    void dumpWhole(const char *directiveName, std::ostream &);

    /// Either aclname parameter from the explicitly configured acl directive or
    /// a label generated for an internal ACL tree node. All Node objects
    /// corresponding to one Squid configuration have unique names.
    /// See also: context() and FindByName().
    SBuf name;

    char *cfgline = nullptr;

private:
    /// Matches the actual data in checklist against this Acl::Node.
    virtual int match(ACLChecklist *checklist) = 0;  // XXX: missing const

    /// whether our (i.e. shallow) match() requires checklist to have a AccessLogEntry
    virtual bool requiresAle() const;
    /// whether our (i.e. shallow) match() requires checklist to have a request
    virtual bool requiresRequest() const;
    /// whether our (i.e. shallow) match() requires checklist to have a reply
    virtual bool requiresReply() const;

    // TODO: Rename to globalOptions(); these are not the only supported options
    /// \returns (linked) 'global' Options supported by this Acl::Node
    virtual const Acl::Options &options() { return Acl::NoOptions(); }

    /// \returns (linked) "line" Options supported by this Acl::Node
    /// \see Acl::Node::options()
    virtual const Acl::Options &lineOptions() { return Acl::NoOptions(); }

    static void ParseNamed(ConfigParser &, NamedAcls &, const SBuf &name);
};

} // namespace Acl

#endif /* SQUID_SRC_ACL_NODE_H */
