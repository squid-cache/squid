/*
 */

#ifndef SQUID_CPU_AFFINITY_H
#define SQUID_CPU_AFFINITY_H

/// set CPU affinity for this process on startup
void CpuAffinityInit();

/// reconfigure CPU affinity for this process
void CpuAffinityReconfigure();

/// check CPU affinity configuration and print warnings if needed
void CpuAffinityCheck();

#endif // SQUID_CPU_AFFINITY_H
