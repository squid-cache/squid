/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_REPL_HEAP_STORE_HEAP_REPLACEMENT_H
#define SQUID_SRC_REPL_HEAP_STORE_HEAP_REPLACEMENT_H

#include "heap.h"

heap_key HeapKeyGen_StoreEntry_LFUDA(void *entry, double age);
heap_key HeapKeyGen_StoreEntry_GDSF(void *entry, double age);
heap_key HeapKeyGen_StoreEntry_LRU(void *entry, double age);

#endif /* SQUID_SRC_REPL_HEAP_STORE_HEAP_REPLACEMENT_H */

