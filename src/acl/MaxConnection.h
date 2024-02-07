/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_ACL_MAXCONNECTION_H
#define SQUID_SRC_ACL_MAXCONNECTION_H

#include "acl/Node.h"

/// \ingroup ACLAPI
class ACLMaxConnection : public Acl::Node
{
    MEMPROXY_CLASS(ACLMaxConnection);

public:
    ACLMaxConnection(char const *);
    ~ACLMaxConnection() override;

    char const *typeString() const override;
    void parse() override;
    int match(ACLChecklist *checklist) override;
    SBufList dump() const override;
    bool empty () const override;
    bool valid () const override;
    void prepareForUse() override;

protected:
    char const *class_;
    int limit;
};

#endif /* SQUID_SRC_ACL_MAXCONNECTION_H */

