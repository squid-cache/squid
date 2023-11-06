/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ACLDENYINFOLIST_H_
#define SQUID_ACLDENYINFOLIST_H_

#include "acl/forward.h"
#include "error/forward.h"
#include "errorpage.h"
#include "mem/forward.h"
#include "sbuf/forward.h"

/// deny_info representation. Currently a POD.
class AclDenyInfoList
{
    MEMPROXY_CLASS(AclDenyInfoList);

public:
    AclDenyInfoList(const char *t, const SBuf &aCfgLocation) {
        err_page_name = xstrdup(t);
        err_page_id = errorReservePageId(t, aCfgLocation);
    }
    ~AclDenyInfoList() {
        xfree(err_page_name);
        while (next) {
            auto *a = next;
            next = a->next;
            a->next = nullptr;
            delete a;
        }
    }
    err_type err_page_id = ERR_NONE;
    char *err_page_name = nullptr;
    SBufList acl_list; ///< ACL names in configured order
    AclDenyInfoList *next = nullptr;
};

#endif /* SQUID_ACLDENYINFOLIST_H_ */

