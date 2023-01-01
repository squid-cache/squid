/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ACLURL_H
#define SQUID_ACLURL_H

#include "acl/Data.h"
#include "acl/Strategised.h"

class ACLUrlStrategy : public ACLStrategy<char const *>
{

public:
    virtual int match (ACLData<char const *> * &, ACLFilledChecklist *);
    virtual bool requiresRequest() const {return true;}
};

#endif /* SQUID_ACLURL_H */

