/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ACLHIERCODEDATA_H
#define SQUID_ACLHIERCODEDATA_H

#include "acl/Acl.h"
#include "acl/Data.h"
#include "hier_code.h"

class ACLHierCodeData : public ACLData<hier_code>
{
    MEMPROXY_CLASS(ACLHierCodeData);

public:
    ACLHierCodeData();
    ACLHierCodeData(ACLHierCodeData const &);
    ACLHierCodeData &operator= (ACLHierCodeData const &);
    virtual ~ACLHierCodeData();
    bool match(hier_code);
    virtual SBufList dump() const;
    void parse();
    bool empty() const;
    virtual ACLData<hier_code> *clone() const;

    /// mask of codes this ACL might match.
    bool values[HIER_MAX];
};

#endif /* SQUID_ACLHIERCODEDATA_H */

