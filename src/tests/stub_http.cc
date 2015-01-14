/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"

#include "HttpReply.h"
#include "HttpRequest.h"

#define STUB_API "http.cc"
#include "tests/STUB.h"

const char * httpMakeVaryMark(HttpRequest * request, HttpReply const * reply) STUB_RETVAL(NULL)

