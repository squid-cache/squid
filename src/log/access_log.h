/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 46    Access Log */

#ifndef SQUID_LOG_ACCESS_LOG_H_
#define SQUID_LOG_ACCESS_LOG_H_

#include "LogTags.h"

class String;
/// count occurrences of the given Via header value
/// XXX: this function preserves all counted values until the next log rotation
void fvdbCountVia(const SBuf &);

void fvdbCountForw(const char *key);

#if HEADERS_LOG
class HttpRequestMethod;
void headersLog(int cs, int pq, const HttpRequestMethod& m, void *data);
#endif

#endif /* SQUID_LOG_ACCESS_LOG_H_ */

