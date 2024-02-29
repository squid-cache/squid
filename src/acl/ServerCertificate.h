/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_ACL_SERVERCERTIFICATE_H
#define SQUID_SRC_ACL_SERVERCERTIFICATE_H

#include "acl/Data.h"
#include "acl/ParameterizedNode.h"
#include "security/forward.h"
#include "ssl/support.h"

namespace Acl
{

/// a "server_cert_fingerprint" ACL
class ServerCertificateCheck: public ParameterizedNode< ACLData<X509 *> >
{
public:
    /* Acl::Node API */
    int match(ACLChecklist *) override;
};

} // namespace Acl

#endif /* SQUID_SRC_ACL_SERVERCERTIFICATE_H */

