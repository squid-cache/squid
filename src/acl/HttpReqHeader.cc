/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "acl/FilledChecklist.h"
#include "acl/HttpHeaderData.h"
#include "acl/HttpReqHeader.h"
#include "HttpRequest.h"

int
Acl::HttpReqHeaderCheck::match(ACLChecklist * const ch)
{
    return data->match(Filled(ch)->request->header);
}

