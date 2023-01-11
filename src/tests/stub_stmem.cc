/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "stmem.h"

#define STUB_API "stmem.cc"
#include "tests/STUB.h"

mem_hdr::mem_hdr() STUB
mem_hdr::~mem_hdr() STUB
size_t mem_hdr::size() const STUB_RETVAL(0)
int64_t mem_hdr::endOffset () const STUB_RETVAL(0)
bool mem_hdr::write (StoreIOBuffer const &writeBuffer) STUB_RETVAL(false)

