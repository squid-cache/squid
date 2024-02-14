/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_ACL_URLPATH_H
#define SQUID_SRC_ACL_URLPATH_H

#include "acl/Strategy.h"

class ACLUrlPathStrategy : public ACLStrategy<char const *>
{

public:
    int match (ACLData<char const *> * &, ACLFilledChecklist *) override;
    bool requiresRequest() const override {return true;}
};

#endif /* SQUID_SRC_ACL_URLPATH_H */

