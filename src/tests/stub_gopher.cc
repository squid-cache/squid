/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"

#define STUB_API "gopher.cc"
#include "tests/STUB.h"

#include "gopher.h"
void gopherStart(FwdState *) STUB
int gopherCachable(const HttpRequest *) STUB

