/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_AUTH_ACLPROXYAUTH_H
#define SQUID_SRC_AUTH_ACLPROXYAUTH_H

#if USE_AUTH

#include "acl/Acl.h"
#include "acl/Checklist.h"
#include "acl/Data.h"

class ACLProxyAuth : public Acl::Node
{
    MEMPROXY_CLASS(ACLProxyAuth);

public:
    static void StartLookup(ACLFilledChecklist &, const Acl::Node &);

    ~ACLProxyAuth() override;
    ACLProxyAuth(ACLData<char const *> *, char const *);

    /* Acl::Node API */
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
    static void LookupDone(void *data);

    /* Acl::Node API */
    const Acl::Options &lineOptions() override;

    int matchProxyAuth(ACLChecklist *);
    ACLData<char const *> *data;
    char const *type_;
};

#endif /* USE_AUTH */
#endif /* SQUID_SRC_AUTH_ACLPROXYAUTH_H */

