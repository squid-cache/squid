/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 22    Refresh Calculation */

#ifndef SQUID_REFRESH_H_
#define SQUID_REFRESH_H_

class RefreshPattern;

void refreshAddToList(const char *, int, time_t, int, time_t);
bool refreshIsCachable(const StoreEntry *);
int refreshCheckHTTP(const StoreEntry *, HttpRequest *);
int refreshCheckICP(const StoreEntry *, HttpRequest *);
int refreshCheckHTCP(const StoreEntry *, HttpRequest *);
int refreshCheckDigest(const StoreEntry *, time_t delta);
time_t getMaxAge(const char *url);
void refreshInit(void);
const RefreshPattern *refreshLimits(const char *url);

#endif /* SQUID_REFRESH_H_ */

