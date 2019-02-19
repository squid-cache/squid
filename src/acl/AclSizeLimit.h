/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ACLSIZELIMIT_H_
#define SQUID_ACLSIZELIMIT_H_

#include "acl/forward.h"
#include "cbdata.h"

/// representation of a class of Size-limit ACLs
class AclSizeLimit
{
    CBDATA_CLASS(AclSizeLimit);

public:
    AclSizeLimit() : next(NULL), aclList(NULL), size(0) {}
    ~AclSizeLimit();

    AclSizeLimit *next;
    ACLList *aclList;
    int64_t size;
};

#endif /* SQUID_ACLSIZELIMIT_H_ */

