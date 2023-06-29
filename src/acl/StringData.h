/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ACLSTRINGDATA_H
#define SQUID_ACLSTRINGDATA_H

#include "acl/Acl.h"
#include "acl/Data.h"
#include "sbuf/SBuf.h"

#include <set>

class ACLStringData : public ACLData<char const *>
{
    MEMPROXY_CLASS(ACLStringData);

public:
    ACLStringData() {}
    ~ACLStringData() override {}
    /// \deprecated use match(SBuf&) instead.
    bool match(char const *) override;
    bool match(const SBuf &);
    SBufList dump() const override;
    void parse() override;
    bool empty() const override;

    /// Insert a string data value
    void insert(const char *);

private:
    typedef std::set<SBuf> StringValues_t;
    StringValues_t stringValues;
};

#endif /* SQUID_ACLSTRINGDATA_H */

