/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ACLDENYINFOLIST_H_
#define SQUID_ACLDENYINFOLIST_H_

#include "err_type.h"

class AclNameList;

/// deny_info representation. Currently a POD.
class AclDenyInfoList
{
public:
    err_type err_page_id;
    char *err_page_name;
    AclNameList *acl_list;
    AclDenyInfoList *next;
};

#endif /* SQUID_ACLDENYINFOLIST_H_ */

