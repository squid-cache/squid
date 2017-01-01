/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ACL_ALL_OF_H
#define SQUID_ACL_ALL_OF_H

#include "acl/InnerNode.h"

namespace Acl
{

/// Configurable all-of ACL. Each ACL line is a conjuction of ACLs.
/// Uses AndNode and OrNode to handle squid.conf configuration where multiple
/// acl all-of lines are always ORed together.
class AllOf: public Acl::InnerNode
{
public:
    MEMPROXY_CLASS(AllOf);

    /* ACL API */
    virtual char const *typeString() const;
    virtual ACL *clone() const;
    virtual void parse();
    virtual SBufList dump() const;

private:
    /* Acl::InnerNode API */
    virtual int doMatch(ACLChecklist *checklist, Nodes::const_iterator start) const;

    static Prototype RegistryProtoype;
    static AllOf RegistryEntry_;
};
MEMPROXY_CLASS_INLINE(Acl::AllOf);

} // namespace Acl

#endif /* SQUID_ACL_ALL_OF_H */

