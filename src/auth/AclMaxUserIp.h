/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ACLMAXUSERIP_H
#define SQUID_ACLMAXUSERIP_H

#if USE_AUTH

#include "acl/Acl.h"
#include "acl/Checklist.h"
#include "auth/UserRequest.h"

class ACLMaxUserIP : public ACL
{
    MEMPROXY_CLASS(ACLMaxUserIP);

public:
    ACLMaxUserIP(char const *theClass);
    ACLMaxUserIP(ACLMaxUserIP const &old);
    ~ACLMaxUserIP();
    ACLMaxUserIP &operator =(ACLMaxUserIP const &);

    virtual ACL *clone() const;
    virtual char const *typeString() const;
    virtual void parse();
    virtual int match(ACLChecklist *cl);
    virtual SBufList dump() const;
    virtual bool empty() const;
    virtual bool valid() const;
    virtual bool requiresRequest() const {return true;}

    int getMaximum() const {return maximum;}

    bool getStrict() const {return flags.isSet(ACL_F_STRICT);}

private:
    static Prototype RegistryProtoype;
    static ACLMaxUserIP RegistryEntry_;
    static ACLFlag SupportedFlags[];

    int match(Auth::UserRequest::Pointer auth_user_request, Ip::Address const &src_addr);
    char const *class_;
    int maximum;
};

#endif /* USE_AUTH */
#endif /* SQUID_ACLMAXUSERIP_H */

