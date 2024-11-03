/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_ACL_PARAMETERIZEDNODE_H
#define SQUID_SRC_ACL_PARAMETERIZEDNODE_H

#include "acl/Node.h"
#include "base/Assure.h"

#include <memory>

namespace Acl
{

/// An ACL that manages squid.conf-configured ACL parameters using a given class
/// P. That P class must support the ACLData<> or equivalent API.
template <class P>
class ParameterizedNode: public Acl::Node
{
public:
    using Parameters = P;

    // to avoid dragging constructor parameters through each derived class, they
    // are set in a leaf class constructor; \sa Acl::FinalizedParameterizedNode
    ParameterizedNode() = default;
    ~ParameterizedNode() override = default;

protected:
    /* Acl::Node API */
    void parse() override { Assure(data); data->parse(); }
    void prepareForUse() override { data->prepareForUse(); }
    SBufList dump() const override { return data->dump(); }
    bool empty() const override { return data->empty(); }
    const Acl::Options &lineOptions() override { return data->lineOptions(); }

    /// Points to items this ACL is configured to match. A derived class ensures
    /// that this pointer is never nil after object construction ends.
    std::unique_ptr<Parameters> data;
};

} // namespace Acl

#endif /* SQUID_SRC_ACL_PARAMETERIZEDNODE_H */

