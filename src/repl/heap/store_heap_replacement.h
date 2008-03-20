/*
 * $Id$
 */
#ifndef _SQUIDINC_STORE_HEAP_REPLACEMENT_H
#define _SQUIDINC_STORE_HEAP_REPLACEMENT_H

#include "heap.h"

extern heap_key HeapKeyGen_StoreEntry_LFUDA(void *entry, double age);
extern heap_key HeapKeyGen_StoreEntry_GDSF(void *entry, double age);
extern heap_key HeapKeyGen_StoreEntry_LRU(void *entry, double age);

#endif /* _SQUIDINC_STORE_HEAP_REPLACEMENT_H */
