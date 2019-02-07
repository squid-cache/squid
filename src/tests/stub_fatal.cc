/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"

#define STUB_API "fatal.cc"
#include "tests/STUB.h"

void fatal(const char *message) STUB
void fatal_common(const char *message) STUB
void fatalf(const char *fmt,...) STUB
void fatalvf(const char *fmt, va_list args) STUB
void fatal_dump(const char *message) STUB

