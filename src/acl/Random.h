/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_ACL_RANDOM_H
#define SQUID_SRC_ACL_RANDOM_H

#include "acl/Node.h"

class ACLRandom : public Acl::Node
{
    MEMPROXY_CLASS(ACLRandom);

public:
    ACLRandom(char const *);
    ~ACLRandom() override;

    char const *typeString() const override;
    void parse() override;
    int match(ACLChecklist *checklist) override;
    SBufList dump() const override;
    bool empty () const override;
    bool valid() const override;

protected:
    double data;        // value to be exceeded before this ACL will match
    char pattern[256];  // pattern from config file. Used to generate 'data'
    char const *class_;
};

#endif /* SQUID_SRC_ACL_RANDOM_H */

