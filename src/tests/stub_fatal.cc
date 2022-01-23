/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"

#define STUB_API "fatal.cc"
#include "tests/STUB.h"

void fatal(const char *) STUB
void fatal_common(const char *) STUB
void fatalf(const char *, ...) STUB
void fatalvf(const char *, va_list) STUB
void fatal_dump(const char *) STUB

