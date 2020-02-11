/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "helper.h"

#define STUB_API "helper.cc"
#include "tests/STUB.h"

void helperSubmit(helper * hlp, const char *buf, HLPCB * callback, void *data) STUB
void helperStatefulSubmit(statefulhelper * hlp, const char *buf, HLPCB * callback, void *data, helper_stateful_server * lastserver) STUB
helper::~helper() STUB
CBDATA_CLASS_INIT(helper);
void helper::packStatsInto(Packable *p, const char *label) const STUB

void helperShutdown(helper * hlp) STUB
void helperStatefulShutdown(statefulhelper * hlp) STUB
void helperOpenServers(helper * hlp) STUB
void helperStatefulOpenServers(statefulhelper * hlp) STUB
void *helperStatefulServerGetData(helper_stateful_server * srv) STUB_RETVAL(NULL)
helper_stateful_server *helperStatefulDefer(statefulhelper * hlp) STUB_RETVAL(NULL)
void helperStatefulReleaseServer(helper_stateful_server * srv) STUB
CBDATA_CLASS_INIT(statefulhelper);

