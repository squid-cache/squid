/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_ACL_USERDATA_H
#define SQUID_SRC_ACL_USERDATA_H

#include "acl/Acl.h"
#include "acl/Data.h"
#include "sbuf/SBuf.h"

#include <set>

class ACLUserData : public ACLData<char const *>
{
    MEMPROXY_CLASS(ACLUserData);

public:
    ~ACLUserData() override {}
    ACLUserData();
    bool match(char const *user) override;
    SBufList dump() const override;
    void parse() override;
    bool empty() const override;

private:
    /// whether parse() is called in a case insensitive context
    static Acl::BooleanOptionValue CaseInsensitive_;

    /* ACLData API */
    const Acl::Options &lineOptions() override;

    typedef std::set<SBuf,bool(*)(const SBuf&, const SBuf&)> UserDataNames_t;
    UserDataNames_t userDataNames;

    struct {
        bool case_insensitive;
        bool required;
    } flags;

};

#endif /* SQUID_SRC_ACL_USERDATA_H */

