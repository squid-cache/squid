/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"

#define STUB_API "time/libtime.la"
#include "tests/STUB.h"

#include "time/Engine.h"
void Time::Engine::tick() STUB

//#include "time/operators.h"

#include "time/forward.h"
struct timeval current_time = {};
double current_dtime = 0.0;
time_t squid_curtime = 0;
time_t getCurrentTime() STUB_RETVAL(0)
int tvSubUsec(struct timeval, struct timeval) STUB_RETVAL(0)
double tvSubDsec(struct timeval, struct timeval) STUB_RETVAL(0.0)
int tvSubMsec(struct timeval, struct timeval) STUB_RETVAL(0)
void tvSub(struct timeval &, struct timeval const &, struct timeval const &) STUB
void tvAdd(struct timeval &, struct timeval const &, struct timeval const &) STUB
void tvAssignAdd(struct timeval &, struct timeval const &) STUB
std::ostream &operator <<(std::ostream &os, const timeval &) STUB_RETVAL(os)
time_t parse_iso3307_time(const char *) STUB_RETVAL(0)
namespace Time
{
const char *FormatStrf(time_t) STUB_RETVAL("")
const char *FormatHttpd(time_t) STUB_RETVAL("")
}
