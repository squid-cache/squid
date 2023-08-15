/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "HttpHdrSc.h"

#define STUB_API "stub_HttpHdrSc.cc"
#include "tests/STUB.h"

void httpHdrScInitModule(void) STUB_NOP
HttpHdrSc* httpHdrScParseCreate(const String & ) STUB_RETVAL(nullptr)
bool HttpHdrSc::parse(const String * ) STUB_RETVAL(false)
void HttpHdrScTarget::packInto(Packable * ) const STUB
void HttpHdrSc::packInto(Packable *) const STUB
void HttpHdrSc::setMaxAge(char const *, int) STUB
void HttpHdrSc::updateStats(StatHist *) const STUB
void httpHdrScTargetStatDumper(StoreEntry *, int, double, double, int) STUB
void httpHdrScStatDumper(StoreEntry *, int, double, double, int) STUB
HttpHdrScTarget * HttpHdrSc::findTarget(const char *) STUB_RETVAL(nullptr)
HttpHdrScTarget * HttpHdrSc::getMergedTarget(const char *) STUB_RETVAL(nullptr)
