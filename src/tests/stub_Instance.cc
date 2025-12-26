/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "Instance.h"
#include "sbuf/Stream.h"

#define STUB_API "Instance.cc"
#include "tests/STUB.h"

void Instance::ThrowIfAlreadyRunning() STUB
void Instance::WriteOurPid() STUB
pid_t Instance::Other() STUB_RETVAL({})

// Return what Instance.cc NamePrefix() would return using default service_name
// and no pid_filename hash value. XXX: Mimicking pid_filename hashing triggers
// ENAMETOOLONG errors on MacOS due to 31-character PSHMNAMLEN limit. We want to
// use "squid-0000" here, but even `/squid-0-tr_rebuild_versions.shm` is one
// character too long! The same limit also affects some Instance.cc NamePrefix()
// callers -- Squid SMP caching support on MacOS is incomplete.
SBuf Instance::NamePrefix(const char * const head, const char * const tail) STUB_RETVAL_NOP(ToSBuf(head, "squid", (tail ? tail : "")))
