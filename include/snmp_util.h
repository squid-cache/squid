/*
 * $Id: snmp_util.h,v 1.6 1998/09/23 17:20:04 wessels Exp $
 */

#ifndef SNMP_UTIL_H
#define SNMP_UTIL_H

/*
 * call a function at regular intervals (in seconds):
 */
extern void snmp_alarm(int ival, void (*handler) (void));


/*
 * service for filedescriptors:
 */

extern void fd_add(int fd, void (*func) (int fd));
extern void fd_service(void);


/* ---------------------------------------------------------------------- */

/*
 * **  SNMP Agent extension for Spacer-Controler Management
 * **
 * **  Copyright (c) 1997 FT/CNET/DES/GRL Olivier Montanuy
 * ** 
 */
/*
 * ** Function to safely copy a string, and ensure the last
 * ** character is always '\0'.
 */
void
     strcpy_safe(char *str, int str_len, char *val);


/*
 * ** Function to get IP address of this agent
 * ** WARNING: this scans all interfaces (slow)
 */
u_long
Util_local_ip_address(void);

/*
 * ** Function to get the current time in seconds
 */
long
     Util_time_now(void);

/*
 * ** Function to determine how long the agent has been running
 * *  (WARNING: this seems rather slow)
 */
long
     Util_time_running();

/*
 * ** Read data from file
 */
int
    Util_file_read(char *file, int offset, char *data, int dataSz);

/*
 * ** Write data into file
 */
int
    Util_file_write(char *file, int offset, char *data, int dataSz);


/* ---------------------------------------------------------------------- */




#endif
