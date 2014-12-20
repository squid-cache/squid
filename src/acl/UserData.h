/*
 * Copyright (C) 1996-2014 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ACLUSERDATA_H
#define SQUID_ACLUSERDATA_H
#include "acl/Acl.h"
#include "acl/Data.h"
#include "splay.h"

class ACLUserData : public ACLData<char const *>
{

public:
    MEMPROXY_CLASS(ACLUserData);

    virtual ~ACLUserData();
    bool match(char const *user);
    virtual SBufList dump() const;
    void parse();
    bool empty() const;
    virtual ACLData<char const *> *clone() const;

    SplayNode<char *> *names;

    struct {
        bool case_insensitive;
        bool required;
    } flags;
};

MEMPROXY_CLASS_INLINE(ACLUserData);

#endif /* SQUID_ACLUSERDATA_H */

