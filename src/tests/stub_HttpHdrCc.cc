/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "HttpHdrCc.h"

#define STUB_API "stub_HttpHdrCc.cc"
#include "tests/STUB.h"

void httpHdrCcStatDumper(StoreEntry *, int, double, double, int) STUB
void httpHdrCcInitModule(void) STUB_NOP
bool HttpHdrCc::parse(const String &) STUB_RETVAL(false)
void httpHdrCcUpdateStats(const HttpHdrCc *, StatHist *) STUB
void HttpHdrCc::packInto(Packable *) const STUB
