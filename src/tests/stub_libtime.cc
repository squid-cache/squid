/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
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

#include "time/gadgets.h"
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
namespace Time
{
time_t ParseIso3307(const char *) STUB_RETVAL(0)
const char *FormatRfc1123(time_t) STUB_RETVAL("")
time_t ParseRfc1123(const char *) STUB_RETVAL(0)
const char *FormatStrf(time_t) STUB_RETVAL("")
const char *FormatHttpd(time_t) STUB_RETVAL("")
}

