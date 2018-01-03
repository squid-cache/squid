/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ACLDENYINFOLIST_H_
#define SQUID_ACLDENYINFOLIST_H_

#include "acl/AclNameList.h"
#include "err_type.h"
#include "errorpage.h"
#include "mem/forward.h"

/// deny_info representation. Currently a POD.
class AclDenyInfoList
{
    MEMPROXY_CLASS(AclDenyInfoList);

public:
    AclDenyInfoList(const char *t) {
        err_page_name = xstrdup(t);
        err_page_id = errorReservePageId(t);
    }
    ~AclDenyInfoList() {
        xfree(err_page_name);
        delete acl_list;
        while (next) {
            auto *a = next;
            next = a->next;
            a->next = nullptr;
            delete a;
        }
    }
    err_type err_page_id = ERR_NONE;
    char *err_page_name = nullptr;
    AclNameList *acl_list = nullptr;
    AclDenyInfoList *next = nullptr;
};

#endif /* SQUID_ACLDENYINFOLIST_H_ */

