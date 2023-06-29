/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "helper.h"

#define STUB_API "helper.cc"
#include "tests/STUB.h"

void helperSubmit(helper *, const char *, HLPCB *, void *) STUB
void helperStatefulSubmit(statefulhelper *, const char *, HLPCB *, void *, uint64_t) STUB
helper::~helper() STUB
CBDATA_CLASS_INIT(helper);
void helper::packStatsInto(Packable *, const char *) const STUB

void helperShutdown(helper *) STUB
void helperStatefulShutdown(statefulhelper *) STUB
void helperOpenServers(helper *) STUB
void helperStatefulOpenServers(statefulhelper *) STUB
CBDATA_CLASS_INIT(statefulhelper);

