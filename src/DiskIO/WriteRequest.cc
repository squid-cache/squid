/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "WriteRequest.h"

CBDATA_CLASS_INIT(WriteRequest);
WriteRequest::WriteRequest(char const *aBuf, off_t anOffset, size_t aLen, FREE *aFree) : buf (aBuf), offset(anOffset), len(aLen), free_func(aFree)
{}

