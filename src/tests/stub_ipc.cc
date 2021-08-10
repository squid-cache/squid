/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "SquidIpc.h"

#define STUB_API "ipc.cc"
#include "tests/STUB.h"

pid_t ipcCreate(int, const char *, const char *const [], const char *, Ip::Address &, int *, int *, void **) STUB_RETVAL(-1)

