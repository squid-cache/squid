/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
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
    void checkForAsync(ACLChecklist *) const override;

private:
    static ProxyAuthLookup instance_;
    static void LookupDone(void *data);
};

class ACLProxyAuth : public ACL
{
    MEMPROXY_CLASS(ACLProxyAuth);

public:
    ~ACLProxyAuth() override;
    ACLProxyAuth(ACLData<char const *> *, char const *);

    /* ACL API */
    char const *typeString() const override;
    void parse() override;
    bool isProxyAuth() const override {return true;}
    int match(ACLChecklist *checklist) override;
    SBufList dump() const override;
    bool valid() const override;
    bool empty() const override;
    bool requiresRequest() const override {return true;}
    int matchForCache(ACLChecklist *checklist) override;

private:
    /* ACL API */
    const Acl::Options &lineOptions() override;

    int matchProxyAuth(ACLChecklist *);
    ACLData<char const *> *data;
    char const *type_;
};

#endif /* USE_AUTH */
#endif /* SQUID_ACLPROXYAUTH_H */

