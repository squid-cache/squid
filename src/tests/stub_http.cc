/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "HttpReply.h"
#include "HttpRequest.h"
#include "sbuf/SBuf.h"

#define STUB_API "http.cc"
#include "tests/STUB.h"

SBuf httpMakeVaryMark(HttpRequest *, HttpReply const *) STUB_RETVAL(SBuf())

