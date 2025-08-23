/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"

#if USE_WCCPv2

#define STUB_API "wccp2.cc"
#include "tests/STUB.h"

#include "wccp2.h"
class StoreEntry;
void dump_wccp2_method(StoreEntry *, const char *, int) STUB
void free_wccp2_method(int *) STUB
void parse_wccp2_amethod(int *) STUB
void dump_wccp2_amethod(StoreEntry *, const char *, int) STUB
void parse_wccp2_service(void *) STUB
void dump_wccp2_service(StoreEntry *, const char *, void *) STUB
void free_wccp2_service(void *) STUB
int check_null_wccp2_service(void *) STUB_RETVAL(0)
void parse_wccp2_service_info(void *) STUB
void dump_wccp2_service_info(StoreEntry *, const char *, void *) STUB
void free_wccp2_service_info(void *) STUB
void free_wccp2_amethod(int *) STUB
void parse_wccp2_method(int *) STUB

#endif /* USE_WCCPv2 */

