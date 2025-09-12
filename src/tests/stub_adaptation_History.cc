/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"

#define STUB_API "adaptation/libadaptation.la"
#include "tests/STUB.h"

#if USE_ADAPTATION
#include "adaptation/History.h"
#endif
#if ICAP_CLIENT
#include "adaptation/icap/History.h"
#endif

#if ICAP_CLIENT
int IcapLogfileStatus = LOG_DISABLE;
Adaptation::Icap::History::History() STUB
#endif

#if USE_ADAPTATION
Adaptation::History::History():
    lastMeta(hoReply),
    allMeta(hoReply),
    theNextServices("")
{
}
#endif

