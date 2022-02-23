/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ACLPROXYAUTH_H
#define SQUID_ACLPROXYAUTH_H

#if USE_AUTH

#include "acl/Acl.h"
#include "acl/Checklist.h"
#include "acl/Data.h"

class ProxyAuthLookup : public ACLChecklist::AsyncState
{

public:
    static ProxyAuthLookup *Instance();
    virtual void checkForAsync(ACLChecklist *) const;

private:
    static ProxyAuthLookup instance_;
    static void LookupDone(void *data);
};

class ACLProxyAuth : public ACL
{
    MEMPROXY_CLASS(ACLProxyAuth);

public:
    ~ACLProxyAuth();
    ACLProxyAuth(ACLData<char const *> *, char const *);

    /* ACL API */
    virtual char const *typeString() const;
    virtual void parse();
    virtual bool isProxyAuth() const {return true;}
    virtual int match(ACLChecklist *checklist);
    virtual SBufList dump() const;
    virtual bool valid() const;
    virtual bool empty() const;
    virtual bool requiresRequest() const {return true;}
    virtual int matchForCache(ACLChecklist *checklist);

private:
    /* ACL API */
    virtual const Acl::Options &lineOptions();

    int matchProxyAuth(ACLChecklist *);
    ACLData<char const *> *data;
    char const *type_;
};

#endif /* USE_AUTH */
#endif /* SQUID_ACLPROXYAUTH_H */

