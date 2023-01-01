/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"

#define STUB_API "cbdata.cc"
#include "tests/STUB.h"

#include "cbdata.h"
void *cbdataInternalAlloc(cbdata_type) STUB_RETVAL(nullptr)
void *cbdataInternalFree(void *) STUB_RETVAL(nullptr)
void cbdataInternalLock(const void *) STUB
void cbdataInternalUnlock(const void *) STUB
int cbdataInternalReferenceDoneValid(void **, void **) STUB_RETVAL(0)
int cbdataReferenceValid(const void *) STUB_RETVAL(0)
cbdata_type cbdataInternalAddType(cbdata_type, const char *, int) STUB_RETVAL(CBDATA_UNKNOWN)

