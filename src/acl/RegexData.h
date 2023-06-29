/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ACLREGEXDATA_H
#define SQUID_ACLREGEXDATA_H

#include "acl/Data.h"

#include <list>

class RegexPattern;

class ACLRegexData : public ACLData<char const *>
{
    MEMPROXY_CLASS(ACLRegexData);

public:
    ~ACLRegexData() override;
    bool match(char const *user) override;
    SBufList dump() const override;
    void parse() override;
    bool empty() const override;

private:
    /// whether parse() is called in a case insensitive context
    static Acl::BooleanOptionValue CaseInsensitive_;

    /* ACLData API */
    const Acl::Options &lineOptions() override;

    std::list<RegexPattern> data;
};

#endif /* SQUID_ACLREGEXDATA_H */

