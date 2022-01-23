/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ACLDATA_H
#define SQUID_ACLDATA_H

#include "acl/Options.h"
#include "sbuf/List.h"

/// Configured ACL parameter(s) (e.g., domain names in dstdomain ACL).
template <class M>
class ACLData
{

public:

    virtual ~ACLData() {}

    /// \returns the flags supported by these ACL parameters (e.g., "-i")
    virtual const Acl::ParameterFlags &supportedFlags() const { return Acl::NoFlags(); }

    virtual bool match(M) =0;
    virtual SBufList dump() const =0;
    virtual void parse() =0;
    virtual ACLData *clone() const =0;
    virtual void prepareForUse() {}

    virtual bool empty() const =0;
};

#endif /* SQUID_ACLDATA_H */

