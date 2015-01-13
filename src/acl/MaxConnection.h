/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ACLMAXCONNECTION_H
#define SQUID_ACLMAXCONNECTION_H

#include "acl/Acl.h"
#include "acl/Checklist.h"

/// \ingroup ACLAPI
class ACLMaxConnection : public ACL
{

public:
    MEMPROXY_CLASS(ACLMaxConnection);

    ACLMaxConnection(char const *);
    ACLMaxConnection(ACLMaxConnection const &);
    ~ACLMaxConnection();
    ACLMaxConnection&operator=(ACLMaxConnection const &);

    virtual ACL *clone()const;
    virtual char const *typeString() const;
    virtual void parse();
    virtual int match(ACLChecklist *checklist);
    virtual SBufList dump() const;
    virtual bool empty () const;
    virtual bool valid () const;
    virtual void prepareForUse();

protected:
    static Prototype RegistryProtoype;
    static ACLMaxConnection RegistryEntry_;
    char const *class_;
    int limit;
};

MEMPROXY_CLASS_INLINE(ACLMaxConnection);

#endif /* SQUID_ACLMAXCONNECTION_H */

