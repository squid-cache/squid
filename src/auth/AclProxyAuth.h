/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
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
public:
    MEMPROXY_CLASS(ACLProxyAuth);

    ~ACLProxyAuth();
    ACLProxyAuth(ACLData<char const *> *, char const *);
    ACLProxyAuth(ACLProxyAuth const &);
    ACLProxyAuth &operator =(ACLProxyAuth const &);

    virtual char const *typeString() const;
    virtual void parse();
    virtual bool isProxyAuth() const {return true;}

    virtual int match(ACLChecklist *checklist);
    virtual SBufList dump() const;
    virtual bool valid() const;
    virtual bool empty() const;
    virtual bool requiresRequest() const {return true;}

    virtual ACL *clone() const;
    virtual int matchForCache(ACLChecklist *checklist);

private:
    static Prototype UserRegistryProtoype;
    static ACLProxyAuth UserRegistryEntry_;
    static Prototype RegexRegistryProtoype;
    static ACLProxyAuth RegexRegistryEntry_;
    int matchProxyAuth(ACLChecklist *);
    ACLData<char const *> *data;
    char const *type_;
};

MEMPROXY_CLASS_INLINE(ACLProxyAuth);

#endif /* USE_AUTH */
#endif /* SQUID_ACLPROXYAUTH_H */

