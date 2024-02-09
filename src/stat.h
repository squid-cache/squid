/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 18    Cache Manager Statistics */

#ifndef SQUID_SRC_STAT_H
#define SQUID_SRC_STAT_H

void statInit(void);
double median_svc_get(int, int);
void pconnHistCount(int, int);
int stat5minClientRequests(void);
double stat5minCPUUsage(void);
double statRequestHitRatio(int minutes);
double statRequestHitMemoryRatio(int minutes);
double statRequestHitDiskRatio(int minutes);
double statByteHitRatio(int minutes);

class StatCounters;
StatCounters *snmpStatGet(int);

#endif /* SQUID_SRC_STAT_H */

