/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_EXTERNALACL_H
#define SQUID_SRC_EXTERNALACL_H

#include "acl/Acl.h"
#include "acl/Checklist.h"
#include "base/RefCount.h"

class external_acl;
class external_acl_data;
class StoreEntry;

class ACLExternal : public Acl::Node
{
    MEMPROXY_CLASS(ACLExternal);

public:
    ACLExternal(char const *);
    ~ACLExternal() override;

    char const *typeString() const override;
    void parse() override;
    int match(ACLChecklist *checklist) override;
    /* This really should be dynamic based on the external class defn */
    bool requiresAle() const override {return true;}
    bool requiresRequest() const override {return true;}

    /* when requiresRequest is made dynamic, review this too */
    //    virtual bool requiresReply() const {return true;}
    bool isProxyAuth() const override;
    SBufList dump() const override;
    bool valid () const override;
    bool empty () const override;

private:
    static void StartLookup(ACLFilledChecklist &, const Acl::Node &);
    static void LookupDone(void *data, const ExternalACLEntryPointer &);
    void startLookup(ACLFilledChecklist *, external_acl_data *, bool inBackground) const;
    Acl::Answer aclMatchExternal(external_acl_data *, ACLFilledChecklist *) const;
    char *makeExternalAclKey(ACLFilledChecklist *, external_acl_data *) const;

    external_acl_data *data;
    char const *class_;
};

void parse_externalAclHelper(external_acl **);
void dump_externalAclHelper(StoreEntry * sentry, const char *name, const external_acl *);
void free_externalAclHelper(external_acl **);
typedef void EAH(void *data, const ExternalACLEntryPointer &result);
void externalAclLookup(ACLChecklist * ch, void *acl_data, EAH * handler, void *data);
void externalAclInit(void);
void externalAclShutdown(void);

#endif /* SQUID_SRC_EXTERNALACL_H */

