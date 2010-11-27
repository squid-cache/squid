/*
 * $Id$
 *
 */

#ifndef SQUID_CPU_AFFINITY_H
#define SQUID_CPU_AFFINITY_H

/// set CPU affinity for this process on startup
SQUIDCEXTERN void CpuAffinityInit();

/// reconfigure CPU affinity for this process
SQUIDCEXTERN void CpuAffinityReconfigure();

/// check CPU affinity configuration and print warnings if needed
SQUIDCEXTERN void CpuAffinityCheck();


#endif // SQUID_CPU_AFFINITY_H
