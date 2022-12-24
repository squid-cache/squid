/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "ipc/Port.h"

#define STUB_API "ipc/Port.cc"
#include "tests/STUB.h"

const char Ipc::strandAddrLabel[] = "-kid";

String Ipc::Port::MakeAddr(char const*, int) STUB_RETVAL("")
String Ipc::Port::CoordinatorAddr() STUB_RETVAL("")

