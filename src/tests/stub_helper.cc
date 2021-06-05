/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
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
void helperStatefulSubmit(statefulhelper *, const char *, HLPCB *, void *, helper_stateful_server *) STUB
helper::~helper() STUB
CBDATA_CLASS_INIT(helper);
void helper::packStatsInto(Packable *, const char *) const STUB

void helperShutdown(helper *) STUB
void helperStatefulShutdown(statefulhelper *) STUB
void helperOpenServers(helper *) STUB
void helperStatefulOpenServers(statefulhelper *) STUB
helper_stateful_server *helperStatefulDefer(statefulhelper *) STUB_RETVAL(nullptr)
void helperStatefulReleaseServer(helper_stateful_server *) STUB
CBDATA_CLASS_INIT(statefulhelper);

