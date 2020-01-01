/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 46    Access Log */

#ifndef SQUID_LOG_ACCESS_LOG_H_
#define SQUID_LOG_ACCESS_LOG_H_

#include "LogTags.h"

void fvdbCountVia(const char *key);
void fvdbCountForw(const char *key);

#if HEADERS_LOG
class HttpRequestMethod;
void headersLog(int cs, int pq, const HttpRequestMethod& m, void *data);
#endif

#endif /* SQUID_LOG_ACCESS_LOG_H_ */

