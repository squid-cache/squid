/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
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

#if USE_CBDATA_DEBUG
void *cbdataInternalAllocDbg(cbdata_type type, const char *, int) STUB_RETVAL(NULL)
void *cbdataInternalFreeDbg(void *p, const char *, int) STUB_RETVAL(NULL)
void cbdataInternalLockDbg(const void *p, const char *, int) STUB
void cbdataInternalUnlockDbg(const void *p, const char *, int) STUB
int cbdataInternalReferenceDoneValidDbg(void **p, void **tp, const char *, int) STUB_RETVAL(0)
#else
void *cbdataInternalAlloc(cbdata_type type) STUB_RETVAL(NULL)
void *cbdataInternalFree(void *p) STUB_RETVAL(NULL)
void cbdataInternalLock(const void *p) STUB
void cbdataInternalUnlock(const void *p) STUB
int cbdataInternalReferenceDoneValid(void **p, void **tp) STUB_RETVAL(0)
#endif

int cbdataReferenceValid(const void *p) STUB_RETVAL(0)
cbdata_type cbdataInternalAddType(cbdata_type type, const char *label, int size, FREE * free_func) STUB_RETVAL(CBDATA_UNKNOWN)

