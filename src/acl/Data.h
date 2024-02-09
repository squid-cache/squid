/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_ACL_DATA_H
#define SQUID_SRC_ACL_DATA_H

#include "acl/Options.h"
#include "sbuf/List.h"

/// Configured ACL parameter(s) (e.g., domain names in dstdomain ACL).
template <class M>
class ACLData
{

public:
    ACLData() = default;
    ACLData(ACLData<M> &&) = delete; // no copying of any kind
    virtual ~ACLData() {}

    /// supported ACL "line" options (e.g., "-i")
    virtual const Acl::Options &lineOptions() { return Acl::NoOptions(); }

    virtual bool match(M) =0;
    virtual SBufList dump() const =0;
    virtual void parse() =0;
    virtual void prepareForUse() {}

    virtual bool empty() const =0;
};

#endif /* SQUID_SRC_ACL_DATA_H */

