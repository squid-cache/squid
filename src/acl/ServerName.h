/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ACLSERVERNAME_H
#define SQUID_ACLSERVERNAME_H

#include "acl/DomainData.h"
#include "acl/ParameterizedNode.h"

class ACLServerNameData : public ACLDomainData {
    MEMPROXY_CLASS(ACLServerNameData);
public:
    ACLServerNameData() : ACLDomainData() {}
    bool match(const char *) override;
};

namespace Acl
{

/// a "ssl::server_name" or "ssl::server_name_regex" ACL
class ServerNameCheck: public ParameterizedNode< ACLData<const char *> >
{
public:
    /* ACL API */
    int match(ACLChecklist *) override;
    bool requiresRequest() const override {return true;}
    const Acl::Options &options() override;
    bool valid() const override;

private:
    Acl::BooleanOptionValue useClientRequested; ///< Ignore server-supplied names
    Acl::BooleanOptionValue useServerProvided; ///< Ignore client-supplied names
    Acl::BooleanOptionValue useConsensus; ///< Ignore mismatching names
};

} // namespace Acl

#endif /* SQUID_ACLSERVERNAME_H */

