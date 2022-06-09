/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "sbuf/SBuf.h"
#include "StoreMeta.h"

#define STUB_API "StoreMeta.cc"
#include "tests/STUB.h"

Store::SwapMetaView::SwapMetaView(const void *, const void *) STUB
void Store::SwapMetaView::checkExpectedLength(size_t) const STUB

#include "StoreMetaMD5.h"
void Store::CheckSwapMetaMd5(const SwapMetaView &, const StoreEntry &) STUB
void Store::GetSwapMetaMd5(const SwapMetaView &, cache_key *) STUB

#include "StoreMetaURL.h"
void Store::CheckSwapMetaUrl(const SwapMetaView &, const StoreEntry &) STUB

#include "StoreMetaVary.h"
SBuf Store::GetNewSwapMetaVaryHeaders(const SwapMetaView &, const StoreEntry &) STUB_RETVAL(SBuf())
