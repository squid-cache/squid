/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_ACL_CONNECTIONSENCRYPTED_H
#define SQUID_SRC_ACL_CONNECTIONSENCRYPTED_H

#include "acl/Acl.h"
#include "acl/Checklist.h"

namespace Acl
{

class ConnectionsEncrypted : public ACL
{
    MEMPROXY_CLASS(ConnectionsEncrypted);

public:
    ConnectionsEncrypted(char const *);
    ~ConnectionsEncrypted() override;

    char const *typeString() const override;
    void parse() override;
    int match(ACLChecklist *checklist) override;
    SBufList dump() const override;
    bool empty () const override;

protected:
    char const *class_;
};

} // namespace Acl

#endif /* SQUID_SRC_ACL_CONNECTIONSENCRYPTED_H */

