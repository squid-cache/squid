/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_EXTERNALACL_H
#define SQUID_EXTERNALACL_H

#include "acl/Checklist.h"
#include "base/RefCount.h"

class external_acl;
class StoreEntry;

/** \todo CLEANUP: kill this typedef. */
typedef struct _external_acl_data external_acl_data;

class ExternalACLLookup : public ACLChecklist::AsyncState
{

public:
    static ExternalACLLookup *Instance();
    virtual void checkForAsync(ACLChecklist *)const;

    // If possible, starts an asynchronous lookup of an external ACL.
    // Otherwise, asserts (or bails if background refresh is requested).
    static void Start(ACLChecklist *checklist, external_acl_data *acl, bool bg);

private:
    static ExternalACLLookup instance_;
    static void LookupDone(void *data, const ExternalACLEntryPointer &result);
};

#include "acl/Acl.h"

class ACLExternal : public ACL
{

public:
    MEMPROXY_CLASS(ACLExternal);

    static void ExternalAclLookup(ACLChecklist * ch, ACLExternal *);

    ACLExternal(char const *);
    ACLExternal(ACLExternal const &);
    ~ACLExternal();
    ACLExternal&operator=(ACLExternal const &);

    virtual ACL *clone()const;
    virtual char const *typeString() const;
    virtual void parse();
    virtual int match(ACLChecklist *checklist);
    /* This really should be dynamic based on the external class defn */
    virtual bool requiresRequest() const {return true;}

    /* when requiresRequest is made dynamic, review this too */
    //    virtual bool requiresReply() const {return true;}
    virtual bool isProxyAuth() const;
    virtual SBufList dump() const;
    virtual bool valid () const;
    virtual bool empty () const;

protected:
    static Prototype RegistryProtoype;
    static ACLExternal RegistryEntry_;
    external_acl_data *data;
    char const *class_;
};

MEMPROXY_CLASS_INLINE(ACLExternal);

void parse_externalAclHelper(external_acl **);
void dump_externalAclHelper(StoreEntry * sentry, const char *name, const external_acl *);
void free_externalAclHelper(external_acl **);
typedef void EAH(void *data, const ExternalACLEntryPointer &result);
void externalAclLookup(ACLChecklist * ch, void *acl_data, EAH * handler, void *data);
void externalAclInit(void);
void externalAclShutdown(void);

#endif /* SQUID_EXTERNALACL_H */

