/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
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
    void checkForAsync(ACLChecklist *)const override;

private:
    static IdentLookup instance_;
    static void LookupDone(const char *ident, void *data);
};

#include "acl/Acl.h"
#include "acl/Data.h"

/// \ingroup ACLAPI
class ACLIdent : public ACL
{
    MEMPROXY_CLASS(ACLIdent);

public:
    ACLIdent(ACLData<char const *> *newData, char const *);
    ~ACLIdent() override;

    /* ACL API */
    char const *typeString() const override;
    void parse() override;
    bool isProxyAuth() const override {return true;}
    int match(ACLChecklist *checklist) override;
    SBufList dump() const override;
    bool empty () const override;

private:
    /* ACL API */
    const Acl::Options &lineOptions() override;

    ACLData<char const *> *data;
    char const *type_;
};

#endif /* USE_IDENT */
#endif /* SQUID_IDENT_ACLIDENT_H */

