/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "acl/FilledChecklist.h"
#include "acl/HierCode.h"
#include "HttpRequest.h"

int
Acl::HierCodeCheck::match(ACLChecklist * const ch)
{
    const auto checklist = Filled(ch);

    return data->match (checklist->request->hier.code);
}

