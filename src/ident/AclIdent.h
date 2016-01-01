/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_IDENT_ACLIDENT_H
#define SQUID_IDENT_ACLIDENT_H

#if USE_IDENT

#include "acl/Checklist.h"

/// \ingroup ACLAPI
class IdentLookup : public ACLChecklist::AsyncState
{

public:
    static IdentLookup *Instance();
    virtual void checkForAsync(ACLChecklist *)const;

private:
    static IdentLookup instance_;
    static void LookupDone(const char *ident, void *data);
};

#include "acl/Acl.h"
#include "acl/Data.h"

/// \ingroup ACLAPI
class ACLIdent : public ACL
{

public:
    MEMPROXY_CLASS(ACLIdent);

    ACLIdent(ACLData<char const *> *newData, char const *);
    ACLIdent (ACLIdent const &old);
    ACLIdent & operator= (ACLIdent const &rhs);
    ~ACLIdent();

    virtual char const *typeString() const;
    virtual void parse();
    virtual bool isProxyAuth() const {return true;}

    virtual int match(ACLChecklist *checklist);
    virtual SBufList dump() const;
    virtual bool empty () const;
    virtual ACL *clone()const;

private:
    static Prototype UserRegistryProtoype;
    static ACLIdent UserRegistryEntry_;
    static Prototype RegexRegistryProtoype;
    static ACLIdent RegexRegistryEntry_;
    ACLData<char const *> *data;
    char const *type_;
};

MEMPROXY_CLASS_INLINE(ACLIdent);

#endif /* USE_IDENT */
#endif /* SQUID_IDENT_ACLIDENT_H */

