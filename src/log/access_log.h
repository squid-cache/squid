/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 46    Access Log */

#ifndef SQUID_SRC_LOG_ACCESS_LOG_H
#define SQUID_SRC_LOG_ACCESS_LOG_H

#include "LogTags.h"
#include "sbuf/forward.h"

/// XXX: these functions preserve all counted values until the next log rotation
/// count occurrences of the given Via header value
void fvdbCountVia(const SBuf &);
/// count occurrences of the given X-Forwarded-For header value
void fvdbCountForwarded(const SBuf &);

#if HEADERS_LOG
class HttpRequestMethod;
void headersLog(int cs, int pq, const HttpRequestMethod& m, void *data);
#endif

#endif /* SQUID_SRC_LOG_ACCESS_LOG_H */

