/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ACLMYPORTNAME_H
#define SQUID_ACLMYPORTNAME_H
#include "acl/Strategy.h"

class ACLMyPortNameStrategy : public ACLStrategy<const char *>
{

public:
    int match (ACLData<MatchType> * &, ACLFilledChecklist *) override;
};

#endif /* SQUID_ACLMYPORTNAME_H */

