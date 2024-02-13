/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_ACL_ANNOTATECLIENT_H
#define SQUID_SRC_ACL_ANNOTATECLIENT_H

#include "acl/Note.h"

namespace Acl
{

/// an "annotate_client" ACL
class AnnotateClientCheck: public Acl::AnnotationCheck
{
public:
    /* Acl::Node API */
    int match(ACLChecklist *) override;
    bool requiresRequest() const override { return true; }
};

} // namespace Acl

#endif /* SQUID_SRC_ACL_ANNOTATECLIENT_H */

