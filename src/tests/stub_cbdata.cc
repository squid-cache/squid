/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "cbdata.h"

#define STUB_API "cbdata.cc"
#include "tests/STUB.h"

void cbdataRegisterWithCacheManager(void) STUB
void *cbdataInternalAlloc(cbdata_type, const char *, int sz) {
    return xcalloc(1, sz);
}
void *cbdataInternalFree(void *p, const char *, int) {
    xfree(p);
    return nullptr;
}
#if USE_CBDATA_DEBUG
void cbdataInternalLockDbg(const void *, const char *, int) STUB
void cbdataInternalUnlockDbg(const void *, const char *, int) STUB
int cbdataInternalReferenceDoneValidDbg(void **, void **, const char *, int) STUB_RETVAL(0)
#else
void cbdataInternalLock(const void *) STUB
void cbdataInternalUnlock(const void *) STUB
int cbdataInternalReferenceDoneValid(void **, void **) STUB_RETVAL(0)
#endif

int cbdataReferenceValid(const void *) STUB_RETVAL(0)
cbdata_type cbdataInternalAddType(cbdata_type, const char *, int) STUB_RETVAL(CBDATA_UNKNOWN)

