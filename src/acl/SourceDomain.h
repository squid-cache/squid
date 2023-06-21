/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ACLSOURCEDOMAIN_H
#define SQUID_ACLSOURCEDOMAIN_H

#include "acl/Data.h"
#include "acl/ParameterizedNode.h"
#include "dns/forward.h"

namespace Acl
{

/// a "srcdomain" or "srcdom_regex" ACL
class SourceDomainCheck: public ParameterizedNode< ACLData<const char *> >
{
public:
    /* ACL API */
    int match(ACLChecklist *) override;
};

} // namespace Acl

class SourceDomainLookup : public ACLChecklist::AsyncState
{

public:
    static SourceDomainLookup *Instance();
    void checkForAsync(ACLChecklist *)const override;

private:
    static SourceDomainLookup instance_;
    static void LookupDone(const char *, const Dns::LookupDetails &, void *);
};

#endif /* SQUID_ACLSOURCEDOMAIN_H */

