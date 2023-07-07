/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ACLSSL_ERROR_H
#define SQUID_ACLSSL_ERROR_H

#include "acl/Data.h"
#include "acl/ParameterizedNode.h"
#include "security/forward.h"

namespace Acl
{

/// an "ssl_error" ACL
class CertificateErrorCheck: public ParameterizedNode< ACLData<const Security::CertErrors *> >
{
public:
    /* ACL API */
    int match(ACLChecklist *) override;
};

} // namespace Acl

#endif /* SQUID_ACLSSL_ERROR_H */

