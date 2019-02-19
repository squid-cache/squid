/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ACLMAXUSERIP_H
#define SQUID_ACLMAXUSERIP_H

#if USE_AUTH

#include "acl/Acl.h"
#include "auth/UserRequest.h"

class ACLMaxUserIP : public ACL
{
    MEMPROXY_CLASS(ACLMaxUserIP);

public:
    explicit ACLMaxUserIP(char const *theClass);

    virtual ACL *clone() const;
    virtual char const *typeString() const;
    virtual const Acl::Options &options();
    virtual void parse();
    virtual int match(ACLChecklist *cl);
    virtual SBufList dump() const;
    virtual bool empty() const;
    virtual bool valid() const;
    virtual bool requiresRequest() const {return true;}

    int getMaximum() const {return maximum;}

private:
    int match(Auth::UserRequest::Pointer auth_user_request, Ip::Address const &src_addr);

public:
    Acl::BooleanOptionValue beStrict; ///< Enforce "one user, one device" policy?

private:
    char const *class_;
    int maximum;
};

#endif /* USE_AUTH */
#endif /* SQUID_ACLMAXUSERIP_H */

