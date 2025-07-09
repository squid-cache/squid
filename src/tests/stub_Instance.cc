/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "Instance.h"
#include "sbuf/SBuf.h"

#define STUB_API "Instance.cc"
#include "tests/STUB.h"

void Instance::ThrowIfAlreadyRunning() STUB
void Instance::WriteOurPid() STUB
pid_t Instance::Other() STUB_RETVAL({})
SBuf Instance::NamePrefix(const char *, const char *) STUB_RETVAL_NOP(SBuf("squid-0"))

