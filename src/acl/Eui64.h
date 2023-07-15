/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ACLEUI64_H
#define SQUID_ACLEUI64_H

#include "acl/Acl.h"

#include <set>

namespace Eui
{
class Eui64;
};

class ACLEui64 : public ACL
{
    MEMPROXY_CLASS(ACLEui64);

public:
    ACLEui64(char const *);
    ~ACLEui64() override {}

    char const *typeString() const override;
    void parse() override;
    int match(ACLChecklist *checklist) override;
    SBufList dump() const override;
    bool empty () const override;

protected:
    typedef std::set<Eui::Eui64> Eui64Data_t;
    Eui64Data_t eui64Data;
    char const *class_;
};

#endif /* SQUID_ACLEUI64_H */

