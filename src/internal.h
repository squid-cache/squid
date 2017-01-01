/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/*
 * DEBUG: section 76    Internal Squid Object handling
 * AUTHOR: Duane, Alex, Henrik
 */

#ifndef SQUID_INTERNAL_H_
#define SQUID_INTERNAL_H_

#include "comm/forward.h"
class HttpRequest;
class StoreEntry;

void internalStart(const Comm::ConnectionPointer &clientConn, HttpRequest *, StoreEntry *);
int internalCheck(const char *urlpath);
int internalStaticCheck(const char *urlpath);
char *internalLocalUri(const char *dir, const char *name);
char *internalRemoteUri(const char *, unsigned short, const char *, const char *);
const char *internalHostname(void);
int internalHostnameIs(const char *);

#endif /* SQUID_INTERNAL_H_ */

