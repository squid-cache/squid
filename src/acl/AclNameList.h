/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ACL_ACLNAMELIST_H_
#define SQUID_ACL_ACLNAMELIST_H_

#include "acl/forward.h"
#include "mem/forward.h"

/// list of name-based ACLs
class AclNameList
{
    MEMPROXY_CLASS(AclNameList);

public:
    AclNameList(const char *t) {
        xstrncpy(name, t, ACL_NAME_SZ-1);
    }
    ~AclNameList() {
        // recursion is okay, these lists are short
        delete next;
    }

    char name[ACL_NAME_SZ];
    AclNameList *next = nullptr;
};
// TODO: convert to a std::list<string>

#endif /* SQUID_ACLNAMELIST_H_ */

