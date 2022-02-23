/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
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
    virtual ~ACLRegexData();
    virtual bool match(char const *user);
    virtual SBufList dump() const;
    virtual void parse();
    virtual bool empty() const;

private:
    /// whether parse() is called in a case insensitive context
    static Acl::BooleanOptionValue CaseInsensitive_;

    /* ACLData API */
    virtual const Acl::Options &lineOptions();

    std::list<RegexPattern> data;
};

#endif /* SQUID_ACLREGEXDATA_H */

