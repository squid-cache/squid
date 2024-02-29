/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "acl/FilledChecklist.h"
#include "acl/Tag.h"
#include "HttpRequest.h"

int
Acl::TagCheck::match(ACLChecklist * const ch)
{
    const auto checklist = Filled(ch);

    if (checklist->request != nullptr)
        return data->match (checklist->request->tag.termedBuf());
    return 0;
}

