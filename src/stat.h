/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 18    Cache Manager Statistics */

#ifndef SQUID_STAT_H_
#define SQUID_STAT_H_

void statInit(void);
void statFreeMemory(void);
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

#endif /* SQUID_STAT_H_ */

