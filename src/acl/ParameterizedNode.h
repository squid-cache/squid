/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_ACL_PARAMETERIZEDNODE_H
#define SQUID_SRC_ACL_PARAMETERIZEDNODE_H

#include "acl/Acl.h"
#include "base/Assure.h"

#include <memory>

namespace Acl
{

/// An ACL that manages configured parameters using a given Parameters class P.
/// That Parameters class must support an ACLData<> or equivalent API.
template <class P>
class ParameterizedNode: public ACL
{
public:
    using Parameters = P;

    // to avoid dragging constructor parameters through each derived class, they
    // are set in a leaf class constructor; \sa Acl::FinalizedParameterizedNode
    ParameterizedNode() = default;
    ~ParameterizedNode() override = default;

protected:
    /* ACL API */
    void parse() override { Assure(parameters); parameters->parse(); }
    void prepareForUse() override { parameters->prepareForUse(); }
    SBufList dump() const override { return parameters->dump(); }
    bool empty() const override { return parameters->empty(); }
    const Acl::Options &lineOptions() override { return parameters->lineOptions(); }

    /// Points to items this ACL is configured to match. A derived class ensures
    /// that this pointer is never nil after the ACL object construction ends.
    std::unique_ptr<Parameters> parameters;

    // XXX: This is a diff reduction hack. Official code often uses poorly named
    // "data" for a data member that should have been named "parameters". New PR
    // code uses "parameters", but we keep this reference to avoid modifying
    // otherwise unchanged official code that uses "data". Before merging this
    // PR, rename new `parameters` to old `data` or vice versa!
    decltype(parameters) &data = parameters;

};

} // namespace Acl

#endif /* SQUID_SRC_ACL_PARAMETERIZEDNODE_H */

