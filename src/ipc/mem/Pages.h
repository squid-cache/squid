/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_IPC_MEM_PAGES_H
#define SQUID_IPC_MEM_PAGES_H

#include "ipc/mem/Page.h"

namespace Ipc
{

namespace Mem
{

/* Single page manipulation */

/// sets page ID and returns true unless no free pages are found
bool GetPage(const PageId::Purpose purpose, PageId &page);

/// makes identified page available as a free page to future GetPage() callers
void PutPage(PageId &page);

/// converts page handler into a temporary writeable shared memory pointer
char *PagePointer(const PageId &page);

/* Limits and statistics */

/// the total number of shared memory pages that can be in use at any time
size_t PageLimit();

/// the total number of shared memory pages that can be in use at any
/// time for given purpose
size_t PageLimit(const int purpose);

/// approximate total number of shared memory pages used now
size_t PageLevel();

/// approximate total number of shared memory pages used now for given purpose
size_t PageLevel(const int purpose);

/// approximate total number of shared memory pages we can allocate now
inline size_t PagesAvailable() { return PageLimit() - PageLevel(); }

/// approximate total number of shared memory pages we can allocate
/// now for given purpose
inline size_t PagesAvailable(const int purpose) { return PageLimit(purpose) - PageLevel(purpose); }

/// returns page size in bytes; all pages are assumed to be the same size
size_t PageSize();

/// claim the need for a number of pages for a given purpose
void NotePageNeed(const int purpose, const int count);

} // namespace Mem

} // namespace Ipc

#endif // SQUID_IPC_MEM_PAGES_H

