/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "MemBuf.h"

#define STUB_API "MemBuf.cc"
#include "tests/STUB.h"

mb_size_t MemBuf::spaceSize() const STUB_RETVAL(0)
mb_size_t MemBuf::potentialSpaceSize() const STUB_RETVAL(0)
void MemBuf::consume(mb_size_t sz) STUB
void MemBuf::appended(mb_size_t sz) STUB
void MemBuf::truncate(mb_size_t sz) STUB
void MemBuf::terminate() STUB
void MemBuf::init(mb_size_t szInit, mb_size_t szMax) STUB
void MemBuf::init() STUB
void MemBuf::clean() STUB
void MemBuf::reset() STUB
int MemBuf::isNull() const STUB_RETVAL(1)
FREE *MemBuf::freeFunc() STUB_RETVAL(NULL)
void MemBuf::append(const char *, int) STUB
void MemBuf::vappendf(const char *fmt, va_list ap) STUB

void memBufReport(MemBuf * mb) STUB

