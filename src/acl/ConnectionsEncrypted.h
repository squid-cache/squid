/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ACL_CONNECTIONS_ENCRYPTED_H
#define SQUID_ACL_CONNECTIONS_ENCRYPTED_H

#include "acl/Acl.h"
#include "acl/Checklist.h"

namespace Acl
{

class ConnectionsEncrypted : public ACL
{
    MEMPROXY_CLASS(ConnectionsEncrypted);

public:
    ConnectionsEncrypted(char const *);
    ConnectionsEncrypted(ConnectionsEncrypted const &);
    virtual ~ConnectionsEncrypted();
    ConnectionsEncrypted &operator =(ConnectionsEncrypted const &);

    virtual ACL *clone()const;
    virtual char const *typeString() const;
    virtual void parse();
    virtual int match(ACLChecklist *checklist);
    virtual SBufList dump() const;
    virtual bool empty () const;

protected:
    static Prototype RegistryProtoype;
    static ConnectionsEncrypted RegistryEntry_;
    char const *class_;
};

} // namespace Acl

#endif /* SQUID_ACL_CONNECTIONS_ENCRYPTED_H */

