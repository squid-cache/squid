#ifndef SNMP_UTIL_H
#define SNMP_UTIL_H


#undef _ANSI_ARGS_
#if (defined(__STDC__) && ! defined(NO_PROTOTYPE)) || defined(USE_PROTOTYPE)
#define _ANSI_ARGS_(x) x
#else
#define _ANSI_ARGS_(x) ()
#endif


/*
 * call a function at regular intervals (in seconds):
 */
extern void snmp_alarm _ANSI_ARGS_((int ival, void (*handler) (void)));


/*
 * service for filedescriptors:
 */

extern void fd_add _ANSI_ARGS_((int fd, void (*func) (int fd)));
extern void fd_service _ANSI_ARGS_((void));


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
strcpy_safe _ANSI_ARGS_((char *str, int str_len, char *val));


/*
 * ** Function to get IP address of this agent
 * ** WARNING: this scans all interfaces (slow)
 */
u_long
Util_local_ip_address _ANSI_ARGS_((void));

/*
 * ** Function to get the current time in seconds
 */
long
Util_time_now _ANSI_ARGS_((void));

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
Util_file_read _ANSI_ARGS_((char *file, int offset, char *data, int dataSz));

/*
 * ** Write data into file
 */
int
Util_file_write _ANSI_ARGS_((char *file, int offset, char *data, int dataSz));


/* ---------------------------------------------------------------------- */













#endif
