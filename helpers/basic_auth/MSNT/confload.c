
/*
 * confload.c
 * (C) 2000 Antonino Iannella, Stellar-X Pty Ltd
 * Released under GPL, see COPYING-2.0 for details.
 * 
 * These routines load the msntauth configuration file.
 * It stores the servers to query, sets the denied and
 * allowed user files, and provides the 
 * authenticating function.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <errno.h>
#include <sys/param.h>
#include <netdb.h>
#include <assert.h>

#include "msntauth.h"
#include "valid.h"

/* Path to configuration file */
#ifndef SYSCONFDIR
#define SYSCONFDIR "/usr/local/squid/etc"
#endif
#define CONFIGFILE   SYSCONFDIR "/msntauth.conf"

/* Maximum number of servers to query. This number can be increased. */
#define MAXSERVERS 5
#define NTHOSTLEN 65

extern char Denyuserpath[MAXPATHLEN];	/* MAXPATHLEN defined in param.h */
extern char Allowuserpath[MAXPATHLEN];

typedef struct _ServerTuple {
    char pdc[NTHOSTLEN];
    char bdc[NTHOSTLEN];
    char domain[NTHOSTLEN];
} ServerTuple;

ServerTuple ServerArray[MAXSERVERS];	/* Array of servers to query */
int Serversqueried = 0;		/* Number of servers queried */

/* Declarations */

static void ProcessLine(char *);
static void AddServer(char *, char *, char *);
static int QueryServerForUser(int, char *, char *);

/*
 * Opens and reads the configuration file.
 * Returns 0 on success, or 1 for error.
 */

int
OpenConfigFile(void)
{
    FILE *ConfigFile;
    char Confbuf[2049];		/* Line reading buffer */

    /* Initialise defaults */

    Serversqueried = 0;
    memset(ServerArray, '\0', sizeof(ServerArray));
    memset(Denyuserpath, '\0', MAXPATHLEN);
    memset(Allowuserpath, '\0', MAXPATHLEN);

    /* Open file */
    if ((ConfigFile = fopen(CONFIGFILE, "r")) == NULL) {
	syslog(LOG_ERR, "OpenConfigFile: Failed to open %s.", CONFIGFILE);
	syslog(LOG_ERR, "%s", strerror(errno));
	return 1;
    }
    /* Read in, one line at a time */
    while (!feof(ConfigFile)) {
	Confbuf[0] = '\0';
	if (NULL == fgets(Confbuf, 2048, ConfigFile))
	    break;
	Confbuf[2048] = '\0';
	ProcessLine(Confbuf);
    }

    /*
     * Check that at least one server is being queried. Report error if not.
     * Denied and allowed user files are hardcoded, so it's fine if they're
     * not set in the confugration file.
     */
    if (Serversqueried == 0) {
	syslog(LOG_ERR, "OpenConfigFile: No servers set in %s. At least one is needed.", CONFIGFILE);
	return 1;
    }
    fclose(ConfigFile);
    return 0;
}

/* Parses a configuration file line. */

static void
ProcessLine(char *Linebuf)
{
    char *Directive;
    char *Param1;
    char *Param2;
    char *Param3;

    /* Ignore empty lines */
    if (strlen(Linebuf) == 0)
	return;

    /* Break up on whitespaces */
    if ((Directive = strtok(Linebuf, " \t\n")) == NULL)
	return;

    /* Check for a comment line. If found, stop . */
    if (Directive[0] == '#')
	return;

    /* Check for server line. Check for 3 parameters. */
    if (strcasecmp(Directive, "server") == 0) {
	Param1 = strtok(NULL, " \t\n");
	if (NULL == Param1) {
	    syslog(LOG_ERR, "ProcessLine: 'server' missing PDC parameter.");
	    return;
	}
	Param2 = strtok(NULL, " \t\n");
	if (NULL == Param2) {
	    syslog(LOG_ERR, "ProcessLine: 'server' missing BDC parameter.");
	    return;
	}
	Param3 = strtok(NULL, " \t\n");
	if (NULL == Param3) {
	    syslog(LOG_ERR, "ProcessLine: 'server' missing domain parameter.");
	    return;
	}
	AddServer(Param1, Param2, Param3);
	return;
    }
    /* Check for denyusers line */
    if (strcasecmp(Directive, "denyusers") == 0) {
	Param1 = strtok(NULL, " \t\n");

	if (NULL == Param1) {
	    syslog(LOG_ERR, "ProcessLine: A 'denyusers' line needs a filename parameter.");
	    return;
	}
	memset(Denyuserpath, '\0', MAXPATHLEN);
	strncpy(Denyuserpath, Param1, MAXPATHLEN - 1);
	return;
    }
    /* Check for allowusers line */
    if (strcasecmp(Directive, "allowusers") == 0) {
	Param1 = strtok(NULL, " \t\n");

	if (NULL == Param1) {
	    syslog(LOG_ERR, "ProcessLine: An 'allowusers' line needs a filename parameter.");
	    return;
	}
	memset(Allowuserpath, '\0', MAXPATHLEN);
	strncpy(Allowuserpath, Param1, MAXPATHLEN - 1);
	return;
    }
    /* Reports error for unknown line */
    syslog(LOG_ERR, "ProcessLine: Ignoring '%s' line.", Directive);
}

/*
 * Adds a server to query to the server array.
 * Checks if the server IP is resolvable.
 * Checks if the number of servers to query is not exceeded.
 * Does not allow parameters longer than NTHOSTLEN.
 */

void
AddServer(char *ParamPDC, char *ParamBDC, char *ParamDomain)
{
    if (Serversqueried == MAXSERVERS) {
	syslog(LOG_ERR, "AddServer: Ignoring '%s' server line; "
	    "too many servers.", ParamPDC);
	return;
    }
    if (gethostbyname(ParamPDC) == NULL) {
	syslog(LOG_ERR, "AddServer: Ignoring host '%s'. "
	    "Cannot resolve its address.", ParamPDC);
	return;
    }
    if (gethostbyname(ParamBDC) == NULL) {
	syslog(LOG_USER | LOG_ERR, "AddServer: Ignoring host '%s'. "
	    "Cannot resolve its address.", ParamBDC);
	return;
    }
    /* NOTE: ServerArray is zeroed in OpenConfigFile() */
    assert(Serversqueried < MAXSERVERS);
    strncpy(ServerArray[Serversqueried].pdc, ParamPDC, NTHOSTLEN - 1);
    strncpy(ServerArray[Serversqueried].bdc, ParamBDC, NTHOSTLEN - 1);
    strncpy(ServerArray[Serversqueried].domain, ParamDomain, NTHOSTLEN - 1);
    Serversqueried++;
}

/*
 * Cycles through all servers to query.
 * Returns 0 if one server could authenticate the user.
 * Returns 1 if no server authenticated the user.
 */

int
QueryServers(char *username, char *password)
{
    int i;
    for (i = 0; i < Serversqueried; i++) {
	if (0 == QueryServerForUser(i, username, password))
	    return 0;
    }
    return 1;
}

/*
 * Attempts to authenticate the user with one server.
 * Logs syslog messages for different errors.
 * Returns 0 on success, non-zero on failure.
 */

/* Define for systems which don't support it, like Solaris */
#ifndef LOG_AUTHPRIV
#define LOG_AUTHPRIV LOG_AUTH
#endif

static int
QueryServerForUser(int x, char *username, char *password)
{
    int result = 1;

    result = Valid_User(username, password, ServerArray[x].pdc,
	ServerArray[x].bdc, ServerArray[x].domain);

    switch (result) {		/* Write any helpful syslog messages */
    case 0:
	break;
    case 1:
	syslog(LOG_AUTHPRIV | LOG_INFO, "Server error when checking %s.",
	    username);
	break;
    case 2:
	syslog(LOG_AUTHPRIV | LOG_INFO, "Protocol error when checking %s.",
	    username);
	break;
    case 3:
	syslog(LOG_AUTHPRIV | LOG_INFO, "Authentication failed for %s.",
	    username);
	break;
    }

    return result;
}

/* Valid_User return codes -
 * 
 * 0 - User authenticated successfully.
 * 1 - Server error.
 * 2 - Protocol error.
 * 3 - Logon error; Incorrect password or username given.
 */
