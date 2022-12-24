/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "ReadRequest.h"

CBDATA_CLASS_INIT(ReadRequest);
ReadRequest::ReadRequest(char *aBuf, off_t anOffset, size_t aLen) : buf (aBuf), offset(anOffset), len(aLen)
{}

