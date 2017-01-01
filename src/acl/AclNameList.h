/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ACL_ACLNAMELIST_H_
#define SQUID_ACL_ACLNAMELIST_H_

#include "acl/forward.h"

/// list of name-based ACLs. Currently a POD.
class AclNameList
{
public:
    char name[ACL_NAME_SZ];
    AclNameList *next;
};
// TODO: convert to a std::list<string>

#endif /* SQUID_ACLNAMELIST_H_ */

