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

void helperSubmit(const Helper::Client::Pointer &, const char *, HLPCB *, void *) STUB
void helperStatefulSubmit(const statefulhelper::Pointer &, const char *, HLPCB *, void *, const Helper::ReservationId &) STUB
Helper::Client::~Client() STUB
void Helper::Client::packStatsInto(Packable *, const char *) const STUB
void Helper::Client::openSessions() STUB

void helperShutdown(const Helper::Client::Pointer &) STUB
void helperStatefulShutdown(const statefulhelper::Pointer &) STUB
void statefulhelper::openSessions() STUB

