/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "ETag.h"

#define STUB_API "ETag.cc"
#include "tests/STUB.h"

int etagParseInit(ETag * , const char *) STUB_RETVAL(0)
bool etagIsStrongEqual(const ETag &, const ETag &) STUB_RETVAL(false)
bool etagIsWeakEqual(const ETag &, const ETag &) STUB_RETVAL(false)

