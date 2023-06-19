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
#include "acl/Data.h"

namespace Acl
{

/// An ACL that manages configured parameters using a given Parameters class.
/// That Parameters class must support an AclData<> or equivalent API.
template <class Parameters>
class ParameterizedNode: public ACL
{
public:
    ParameterizedNode() = default;
    ~ParameterizedNode() override = default;

protected:
    /* ACL API */
    void prepareForUse() override { parameters.prepareForUse();}
    void parse() override { parameters.parse(); }
    SBufList dump() const override { return parameters.dump(); }
    bool empty() const override { return parameters.empty(); }
    const Acl::Options &lineOptions() override { return parameters.lineOptions(); }

    Parameters parameters;
};

} // namespace Acl

#endif /* SQUID_SRC_ACL_PARAMETERIZEDNODE_H */

