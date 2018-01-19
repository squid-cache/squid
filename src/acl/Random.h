/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ACL_RANDOM_H
#define SQUID_ACL_RANDOM_H

#include "acl/Acl.h"
#include "acl/Checklist.h"

/// \ingroup ACLAPI
class ACLRandom : public ACL
{

public:
    MEMPROXY_CLASS(ACLRandom);

    ACLRandom(char const *);
    ACLRandom(ACLRandom const &);
    ~ACLRandom();
    ACLRandom&operator=(ACLRandom const &);

    virtual ACL *clone()const;
    virtual char const *typeString() const;
    virtual void parse();
    virtual int match(ACLChecklist *checklist);
    virtual SBufList dump() const;
    virtual bool empty () const;
    virtual bool valid() const;

protected:
    static Prototype RegistryProtoype;
    static ACLRandom RegistryEntry_;
    double data;        // value to be exceeded before this ACL will match
    char pattern[256];  // pattern from config file. Used to generate 'data'
    char const *class_;
};

MEMPROXY_CLASS_INLINE(ACLRandom);

#endif /* SQUID_ACL_RANDOM_H */

