/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SNMP_UTIL_H
#define SQUID_SNMP_UTIL_H

#ifdef __cplusplus
extern "C" {
#endif

/* call a function at regular intervals (in seconds): */
extern void snmp_alarm(int ival, void (*handler) (void));

/* service for filedescriptors: */

extern void fd_add(int fd, void (*func) (int fd));
extern void fd_service(void);

/* ---------------------------------------------------------------------- */

/*
 * SNMP Agent extension for Spacer-Controler Management
 *
 * Copyright (c) 1997 FT/CNET/DES/GRL Olivier Montanuy
 */

/* Function to safely copy a string, and ensure the last
 * character is always '\0'. */
void strcpy_safe(char *str, int str_len, char *val);

/* Function to get IP address of this agent
 * WARNING: this scans all interfaces (slow) */
u_long Util_local_ip_address(void);

/* Function to get the current time in seconds */
long Util_time_now(void);

/* Function to determine how long the agent has been running
 * (WARNING: this seems rather slow) */
long Util_time_running();

/* Read data from file */
int Util_file_read(char *file, int offset, char *data, int dataSz);

/* Write data into file */
int Util_file_write(char *file, int offset, char *data, int dataSz);

/* ---------------------------------------------------------------------- */

#ifdef __cplusplus
}
#endif
#endif /* SQUID_SNMP_UTIL_H */

