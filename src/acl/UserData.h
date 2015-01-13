/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
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
    MEMPROXY_CLASS(ACLUserData);

public:
    virtual ~ACLUserData();
    bool match(char const *user);
    virtual SBufList dump() const;
    void parse();
    bool empty() const;
    virtual ACLData<char const *> *clone() const;

    Splay<char *> *names;

    struct {
        bool case_insensitive;
        bool required;
    } flags;
};

#endif /* SQUID_ACLUSERDATA_H */

