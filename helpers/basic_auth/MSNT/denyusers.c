
/*
 * denyusers.c
 * (C) 2000 Antonino Iannella, Stellar-X Pty Ltd
 * Released under GPL, see COPYING-2.0 for details.
 * 
 * These routines are to block users attempting to use the proxy which
 * have been explicitly denied by the system administrator.
 * Routines at the bottom also use the allowed user functions.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>
#include <time.h>
#include <ctype.h>
#include <sys/param.h>

#define NAMELEN     50		/* Maximum username length */

/* Global variables */

char *DeniedUsers;		/* Pointer to string of denied users */
off_t DenyUserSize;		/* Size of denied user file */
struct stat FileBuf;		/* Stat data buffer */
time_t LastModTime;		/* Last denied user file modification time */

char Denyuserpath[MAXPATHLEN];	/* MAXPATHLEN defined in param.h */

/* Function declarations */

int Read_denyusers();
int Check_ifuserdenied(char *);
int Check_user(char *);
void Checktimer();
void Check_forchange();
void Check_fordenychange();
extern void Check_forallowchange();	/* For allowed users */
extern int Check_ifuserallowed(char *);

/*
 * Reads Denyuserpath for all users to be excluded.
 * Returns 0 if the user list was successfully loaded,
 * and 1 in case of error.
 * Logs any messages to the syslog daemon.
 */

int
Read_denyusers()
{
    FILE *DFile;		/* Denied user file pointer */
    off_t DPos = 0;		/* File counter */
    char DChar;			/* Character buffer */

    /* Stat the file. If it does not exist, save the size as zero.
     * Clear the denied user string. Return. */
    if (stat(Denyuserpath, &FileBuf) == -1) {
	if (errno == ENOENT) {
	    LastModTime = (time_t) 0;
	    DenyUserSize = 0;
	    free(DeniedUsers);
	    DeniedUsers = malloc(sizeof(char));
	    DeniedUsers[0] = '\0';
	    return 0;
	} else {
	    syslog(LOG_USER | LOG_ERR, strerror(errno));
	    return 1;
	}
    }
    /* If it exists, save the modification time and size */
    LastModTime = FileBuf.st_mtime;
    DenyUserSize = FileBuf.st_size;

    /* Handle the special case of a zero length file */
    if (DenyUserSize == 0) {
	free(DeniedUsers);
	DeniedUsers = malloc(sizeof(char));
	DeniedUsers[0] = '\0';
	return 0;
    }
    /* Free and allocate space for a string to store the denied usernames */
    free(DeniedUsers);

    if ((DeniedUsers = malloc(sizeof(char) * (DenyUserSize + 3))) == NULL) {
	syslog(LOG_USER | LOG_ERR, "Read_denyusers: malloc(DeniedUsers) failed.");
	return 1;
    }
    /* Open the denied user file. Report any errors. */

    if ((DFile = fopen(Denyuserpath, "r")) == NULL) {
	syslog(LOG_USER | LOG_ERR, "Read_denyusers: Failed to open denied user file.");
	syslog(LOG_USER | LOG_ERR, strerror(errno));
	return 1;
    }
    /* Read user names into the DeniedUsers string.
     * Make sure each string is delimited by a space. */

    DeniedUsers[DPos++] = ' ';

    while (!feof(DFile)) {
	if ((DChar = fgetc(DFile)) == EOF)
	    break;
	else {
	    if (isspace(DChar))
		DeniedUsers[DPos++] = ' ';
	    else
		DeniedUsers[DPos++] = toupper(DChar);
	}
    }

    DeniedUsers[DPos++] = ' ';
    DeniedUsers[DPos] = '\0';
    fclose(DFile);
    return 0;
}

/*
 * Check to see if the username provided by Squid appears in the denied
 * user list. Returns 0 if the user was not found, and 1 if they were.
 */

int
Check_ifuserdenied(char *ConnectingUser)
{
    static char CUBuf[NAMELEN + 1];
    static char CUBuf1[NAMELEN + 1];
    static int x;
    static char DenyMsg[256];

    /* If user string is empty, deny */
    if (ConnectingUser[0] == '\0')
	return 1;

    /* If denied user list is empty, allow */
    if (DenyUserSize == 0)
	return 0;

    /* Check if username string is found in the denied user list.
     * If so, deny. If not, allow. Reconstruct the username
     * to have whitespace, to avoid finding wrong string subsets. */

    sscanf(ConnectingUser, " %s ", CUBuf1);
    sprintf(CUBuf, " %s ", CUBuf1);

    for (x = 0; x <= strlen(CUBuf); x++)
	CUBuf[x] = toupper(CUBuf[x]);

    if (strstr(DeniedUsers, CUBuf) == NULL)
	return 0;
    else {
	sprintf(DenyMsg, "Denied access to user '%s'.", CUBuf1);
	syslog(LOG_USER | LOG_ERR, DenyMsg);
	return 1;
    }
}

/*
 * Checks if there has been a change in the denied user file.
 * If the modification time has changed, then reload the denied user list.
 * This function is called by the SIGHUP signal handler.
 */

void
Check_fordenychange()
{
    struct stat ChkBuf;		/* Stat data buffer */

    /* Stat the denied user file. If it cannot be accessed, return. */

    if (stat(Denyuserpath, &ChkBuf) == -1) {
	if (errno == ENOENT) {
	    LastModTime = (time_t) 0;
	    DenyUserSize = 0;
	    free(DeniedUsers);
	    DeniedUsers = malloc(sizeof(char));
	    DeniedUsers[0] = '\0';
	    return;
	} else {		/* Report error when accessing file */
	    syslog(LOG_USER | LOG_ERR, strerror(errno));
	    return;
	}
    }
    /* If found, compare the modification time with the previously-recorded
     * modification time.
     * If the modification time has changed, reload the denied user list.
     * Log a message of its actions. */

    if (ChkBuf.st_mtime != LastModTime) {
	syslog(LOG_USER | LOG_INFO, "Check_fordenychange: Reloading denied user list.");
	Read_denyusers();
    }
}

/*
 * Decides if a user is denied or allowed.
 * If they have been denied, or not allowed, return 1.
 * Else return 0.
 */

int
Check_user(char *ConnectingUser)
{
    if (Check_ifuserdenied(ConnectingUser) == 1)
	return 1;

    if (Check_ifuserallowed(ConnectingUser) == 0)
	return 1;

    return 0;
}

/*
 * Checks the denied and allowed user files for change.
 * This function is invoked when a SIGHUP signal is received.
 * It is also run after every 60 seconds, at the next request.
 */

void
Check_forchange()
{
    Check_fordenychange();
    Check_forallowchange();
}

/*
 * Checks the timer. If longer than 1 minute has passed since the last
 * time someone has accessed the proxy, then check for changes in the
 * denied user file. If longer than one minute hasn't passed, return.
 */

void
Checktimer()
{
    static time_t Lasttime;	/* The last time the timer was checked */
    static time_t Currenttime;	/* The current time */

    Currenttime = time(NULL);

    /* If timeout has expired, check the denied user file, else return */
    if (difftime(Currenttime, Lasttime) < 60)
	return;
    else {
	Check_forchange();
	Lasttime = Currenttime;
    }
}
