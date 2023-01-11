/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ACLUSERDATA_H
#define SQUID_ACLUSERDATA_H

#include "acl/Acl.h"
#include "acl/Data.h"
#include "sbuf/SBuf.h"

#include <set>

class ACLUserData : public ACLData<char const *>
{
    MEMPROXY_CLASS(ACLUserData);

public:
    virtual ~ACLUserData() {}
    ACLUserData();
    bool match(char const *user);
    virtual SBufList dump() const;
    void parse();
    virtual const Acl::ParameterFlags &supportedFlags() const;
    bool empty() const;
    virtual ACLData<char const *> *clone() const;

private:

    typedef std::set<SBuf,bool(*)(const SBuf&, const SBuf&)> UserDataNames_t;
    UserDataNames_t userDataNames;

    struct {
        bool case_insensitive;
        bool required;
    } flags;

};

#endif /* SQUID_ACLUSERDATA_H */

