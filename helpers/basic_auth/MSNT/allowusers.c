
/*
 * allowusers.c
 * (C) 2000 Antonino Iannella, Stellar-X Pty Ltd
 * Released under GPL, see COPYING-2.0 for details.
 * 
 * These routines are to allow users attempting to use the proxy which
 * have been explicitly allowed by the system administrator.
 * The code originated from denyusers.c.
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

char *AllowedUsers;		/* Pointer to string of allowed users */
off_t AllowUserSize;		/* Size of allowed users file */
struct stat FileBuf;		/* Stat data buffer */
time_t LastModTime;		/* Last allowed user file modification time */

char Allowuserpath[MAXPATHLEN];	/* MAXPATHLEN defined in param.h */

/* Function declarations */

int Read_allowusers();
int Check_ifuserallowed(char *);
void Checkforchange();
void Checktimer();

/*
 * Reads the allowed users file for all users to be permitted.
 * Returns 0 if the user list was successfully loaded,
 * and 1 in case of error.
 * Logs any messages to the syslog daemon.
 */

int
Read_allowusers()
{
    FILE *AFile;		/* Allowed users file pointer */
    off_t APos = 0;		/* File counter */
    char AChar;			/* Character buffer */

    /* Stat the file. If it does not exist, save the size as zero.
     * Clear the allowed user string. Return. */
    if (stat(Allowuserpath, &FileBuf) == -1) {
	if (errno == ENOENT) {
	    LastModTime = (time_t) 0;
	    AllowUserSize = 0;
	    free(AllowedUsers);
	    AllowedUsers = malloc(sizeof(char));
	    AllowedUsers[0] = '\0';
	    return 0;
	} else {
	    syslog(LOG_USER | LOG_ERR, strerror(errno));
	    return 1;
	}
    }
    /* If it exists, save the modification time and size */
    LastModTime = FileBuf.st_mtime;
    AllowUserSize = FileBuf.st_size;

    /* Handle the special case of a zero length file */
    if (AllowUserSize == 0) {
	free(AllowedUsers);
	AllowedUsers = malloc(sizeof(char));
	AllowedUsers[0] = '\0';
	return 0;
    }
    /* Free and allocate space for a string to store the allowed usernames */
    free(AllowedUsers);

    if ((AllowedUsers = malloc(sizeof(char) * (AllowUserSize + 3))) == NULL) {
	syslog(LOG_USER | LOG_ERR, "Read_allowusers: malloc(AllowedUsers) failed.");
	return 1;
    }
    /* Open the allowed users file. Report any errors. */

    if ((AFile = fopen(Allowuserpath, "r")) == NULL) {
	syslog(LOG_USER | LOG_ERR, "Read_allowusers: Failed to open allowed user file.");
	syslog(LOG_USER | LOG_ERR, strerror(errno));
	return 1;
    }
    /* Read user names into the AllowedUsers string.
     * Make sure each string is delimited by a space. */

    AllowedUsers[APos++] = ' ';

    while (!feof(AFile)) {
	if ((AChar = fgetc(AFile)) == EOF)
	    break;
	else {
	    if (isspace(AChar))
		AllowedUsers[APos++] = ' ';
	    else
		AllowedUsers[APos++] = toupper(AChar);
	}
    }

    AllowedUsers[APos++] = ' ';
    AllowedUsers[APos] = '\0';
    fclose(AFile);
    return 0;
}

/*
 * Check to see if the username provided by Squid appears in the allowed
 * user list. Returns 0 if the user was not found, and 1 if they were.
 */

int
Check_ifuserallowed(char *ConnectingUser)
{
    static char CUBuf[NAMELEN + 1];
    static char CUBuf1[NAMELEN + 1];
    static int x;
    static char AllowMsg[256];

    /* If user string is empty, allow */
    if (ConnectingUser[0] == '\0')
	return 1;

    /* If allowed user list is empty, allow all users.
     * If no users are supposed to be using the proxy, stop squid instead. */
    if (AllowUserSize == 0)
	return 1;

    /* Check if username string is found in the allowed user list.
     * If so, allow. If not, deny. Reconstruct the username
     * to have whitespace, to avoid finding wrong string subsets. */

    sscanf(ConnectingUser, " %s ", CUBuf1);
    sprintf(CUBuf, " %s ", CUBuf1);

    for (x = 0; x <= strlen(CUBuf); x++)
	CUBuf[x] = toupper(CUBuf[x]);

    if (strstr(AllowedUsers, CUBuf) != NULL)
	return 1;
    else {			/* If NULL, they are not allowed to use the proxy */
	sprintf(AllowMsg, "Did not allow access to user '%s'.", CUBuf1);
	syslog(LOG_USER | LOG_ERR, AllowMsg);
	return 0;
    }
}

/*
 * Checks if there has been a change in the allowed users file.
 * If the modification time has changed, then reload the allowed user list.
 * This function is called by the SIGHUP signal handler.
 */

void
Check_forallowchange()
{
    struct stat ChkBuf;		/* Stat data buffer */

    /* Stat the allowed users file. If it cannot be accessed, return. */

    if (stat(Allowuserpath, &ChkBuf) == -1) {
	if (errno == ENOENT) {
	    LastModTime = (time_t) 0;
	    AllowUserSize = 0;
	    free(AllowedUsers);
	    AllowedUsers = malloc(sizeof(char));
	    AllowedUsers[0] = '\0';
	    return;
	} else {		/* Report error when accessing file */
	    syslog(LOG_USER | LOG_ERR, strerror(errno));
	    return;
	}
    }
    /* If found, compare the modification time with the previously-recorded
     * modification time.
     * If the modification time has changed, reload the allowed user list.
     * Log a message of its actions. */

    if (ChkBuf.st_mtime != LastModTime) {
	syslog(LOG_USER | LOG_INFO, "Check_forallowchange: Reloading allowed user list.");
	Read_allowusers();
    }
}
