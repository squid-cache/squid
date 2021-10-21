/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 52    URN Trivial HTTP (THTTP) resolution protocol */

#ifndef SQUID_SRC_URN_H
#define SQUID_SRC_URN_H

#if USE_URN_THTTP

#include "log/forward.h"

class HttpRequest;
class StoreEntry;

void urnStart(HttpRequest *, StoreEntry *, const AccessLogEntryPointer &ale);

#endif /* USE_URN_THTTP */
#endif /* SQUID_SRC_URN_H */

