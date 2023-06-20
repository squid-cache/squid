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

#include <memory>
#include <utility>

namespace Acl
{

/// An ACL that manages configured parameters using a given Parameters class.
/// That Parameters class must support an AclData<> or equivalent API.
template <class Parameters>
class ParameterizedNode: public ACL
{
public:
    /// constructor for kids that support multiple Parameters-derived types
    /// and/or need custom Parameters construction code
    ParameterizedNode(char const *typeName, Parameters *params):
        parameters(params),
        typeName_(typeName)
    {
    }

    /// convenience constructor for kids that specify specific/leaf Parameters
    /// type (that also has the right default constructor)
    explicit ParameterizedNode(char const *typeName):
        ParameterizedNode(typeName, new Parameters())
    {
    }

    ~ParameterizedNode() override = default;

protected:
    /* ACL API */
    void prepareForUse() override { parameters->prepareForUse(); }
    void parse() override { parameters->parse(); }
    SBufList dump() const override { return parameters->dump(); }
    bool empty() const override { return parameters->empty(); }
    const Acl::Options &lineOptions() override { return parameters->lineOptions(); }
    char const *typeString() const override { return typeName_; }

    /// items this ACL is configured to match; never nil
    const std::unique_ptr<Parameters> parameters;

private:
    /// the "acltype" name that our creator uses for this ACL type
    const TypeName typeName_;
};

} // namespace Acl

#endif /* SQUID_SRC_ACL_PARAMETERIZEDNODE_H */

