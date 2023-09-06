/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ACLHTTPREPHEADER_H
#define SQUID_ACLHTTPREPHEADER_H

#include "acl/Data.h"
#include "acl/ParameterizedNode.h"
#include "HttpHeader.h"

namespace Acl
{

/// a "rep_header" ACL
class HttpRepHeaderCheck: public ParameterizedNode< ACLData<HttpHeader*> >
{
public:
    /* ACL API */
    int match(ACLChecklist *) override;
    bool requiresReply() const override { return true; }
};

} // namespace Acl

#endif /* SQUID_ACLHTTPREPHEADER_H */

