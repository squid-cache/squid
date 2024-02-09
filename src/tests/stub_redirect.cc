/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "redirect.h"

#define STUB_API "redirect.cc"
#include "tests/STUB.h"

void redirectInit(void) STUB
void redirectShutdown(void) STUB
void redirectStart(ClientHttpRequest *, HLPCB *, void *) STUB
void storeIdStart(ClientHttpRequest *, HLPCB *, void *) STUB

