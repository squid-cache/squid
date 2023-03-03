/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ACLMAXCONNECTION_H
#define SQUID_ACLMAXCONNECTION_H

#include "acl/Acl.h"

/// \ingroup ACLAPI
class ACLMaxConnection : public ACL
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

#endif /* SQUID_ACLMAXCONNECTION_H */

