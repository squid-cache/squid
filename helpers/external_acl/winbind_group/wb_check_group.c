/*
 * $Id: wb_check_group.c,v 1.9 2003/02/11 14:34:41 hno Exp $
 *
 * This is a helper for the external ACL interface for Squid Cache
 * Copyright (C) 2002 Guido Serassio <squidnt@serassio.it>
 * Based on previous work of Rodrigo Albani de Campos
 * 
 * It reads from the standard input the domain username and a list of
 * groups and tries to match it against the groups membership of the
 * specified username.
 *
 * Returns `OK' if the user belongs to a group or `ERR' otherwise, as
 * described on http://devel.squid-cache.org/ external_acl/config.html
 *
 * Requires Samba 2.2.4 or later with Winbindd.
 * 
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111, USA.
 *
 */
#include "wbntlm.h"
#include "util.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "nsswitch/winbind_nss_config.h"
#include "nsswitch/winbindd_nss.h"

#define BUFSIZE 8192		/* the stdin buffer size */
char debug_enabled=0;
char *myname;
pid_t mypid;

NSS_STATUS winbindd_request(int req_type,
			    struct winbindd_request *request,
			    struct winbindd_response *response);

static char *
strwordtok(char *buf, char **t)
{
    unsigned char *word = NULL;
    unsigned char *p = (unsigned char *) buf;
    unsigned char *d;
    unsigned char ch;
    int quoted = 0;
    if (!p)
	p = (unsigned char *) *t;
    if (!p)
	goto error;
    while (*p && isspace(*p))
	p++;
    if (!*p)
	goto error;
    word = d = p;
    while ((ch = *p)) {
	switch (ch) {
	case '\\':
	    p++;
	    *d++ = ch = *p;
	    if (ch)
		p++;
	    break;
	case '"':
	    quoted = !quoted;
	    p++;
	    break;
	default:
	    if (!quoted && isspace(*p)) {
		p++;
		goto done;
	    }
	    *d++ = *p++;
	    break;
	}
    }
  done:
    *d++ = '\0';
  error:
    *t = (char *) p;
    return (char *) word;
}



/* Convert sid to string */

char * wbinfo_lookupsid(char * group, char *sid)
{
    struct winbindd_request request;
    struct winbindd_response response;

    memset(&request,0,sizeof(struct winbindd_request));
    memset(&response,0,sizeof(struct winbindd_response));

    /* Send off request */

    strncpy(request.data.sid, sid,sizeof(fstring)-1);

    if (winbindd_request(WINBINDD_LOOKUPSID, &request, &response) !=
	NSS_STATUS_SUCCESS)
	return NULL;

    /* Display response */

    strcpy(group,response.data.name.name);
    return group;
}


/* Convert gid to sid */

char * wbinfo_gid_to_sid(char * sid, gid_t gid)
{
    struct winbindd_request request;
    struct winbindd_response response;

    memset(&request,0,sizeof(struct winbindd_request));
    memset(&response,0,sizeof(struct winbindd_response));

    /* Send request */

    request.data.gid = gid;

    if (winbindd_request(WINBINDD_GID_TO_SID, &request, &response) !=
        NSS_STATUS_SUCCESS)
    	return NULL;

    /* Display response */

    strcpy(sid, response.data.sid.sid);

    return sid;
}

/* returns 0 on match, -1 if no match */
static inline int strcmparray(const char *str, const char **array)
{
    while (*array) {
    	debug("Windows group: %s, Squid group: %s\n", str, *array);
	if (strcmp(str, *array) == 0)
	    return 0;
	array++;
    }
    return -1;
}

/* returns 1 on success, 0 on failure */
int
Valid_Groups(char *UserName, const char **UserGroups)
{
    struct winbindd_request request;
    struct winbindd_response response;
    NSS_STATUS result;
    int i;
    char sid[FSTRING_LEN];
    char group[FSTRING_LEN];
    int match = 0;
	
    memset(&request,0,sizeof(struct winbindd_request));
    memset(&response,0,sizeof(struct winbindd_response));

    /* Send request */

    strncpy(request.data.username,UserName,sizeof(fstring)-1);

    result = winbindd_request(WINBINDD_GETGROUPS, &request, &response);

    if (result != NSS_STATUS_SUCCESS)
	return match;

    for (i = 0; i < response.data.num_entries; i++) {
    	if ((wbinfo_gid_to_sid(sid, (int)((gid_t *)response.extra_data)[i])) != NULL) {
    	    debug("SID: %s\n", sid);	
	    if (wbinfo_lookupsid(group,sid) == NULL)
    		break;
	    if (strcmparray(group, UserGroups) == 0) {
		match = 1;
		break;
	    }
	} else {
	    return match;
	}
    }
    SAFE_FREE(response.extra_data);

    return match;
}

static void
usage(char *program)
{
    fprintf(stderr,"Usage: %s [-d] [-h]\n"
	    	" -d      enable debugging\n"
		" -h      this message\n",
		program);
}

void
process_options(int argc, char *argv[])
{
    int opt;

    opterr = 0;
    while (-1 != (opt = getopt(argc, argv, "dh"))) {
	switch (opt) {
	case 'd':
	    debug_enabled = 1;
	    break;
	case 'h':
	    usage(argv[0]);
	    exit(0);
	case '?':
	    opt = optopt;
	    /* fall thru to default */
	default:
	    warn("Unknown option: -%c\n\n", opt);
	    usage(argv[0]);
	    exit(1);
	    break;		/* not reached */
	}
    }
    return;
}

int
main (int argc, char *argv[])
{
    char *p, *t;
    char buf[BUFSIZE];
    char *username;
    char *group;
    int err = 0;
    const char *groups[512];
    int n;

    if (argc > 0) {	/* should always be true */
	myname=strrchr(argv[0],'/');
	if (myname==NULL)
	    myname=argv[0];
    } else {
        myname="(unknown)";
    }
    mypid=getpid();

    /* make standard output line buffered */
    setvbuf (stdout, NULL, _IOLBF, 0);

    /* Check Command Line */
    process_options(argc, argv);

    debug("External ACL winbindd group helper build " __DATE__ ", " __TIME__
    " starting up...\n");
 
    /* Main Loop */
    while (fgets (buf, BUFSIZE, stdin))
    {
	if (NULL == strchr(buf, '\n')) {
	    err = 1;
	    continue;
	}
	if (err) {
	    warn("Oversized message\n");
	    goto error;
	}

	if ((p = strchr(buf, '\n')) != NULL)
	    *p = '\0';		/* strip \n */
	if ((p = strchr(buf, '\r')) != NULL)
	    *p = '\0';		/* strip \r */

	debug("Got '%s' from Squid (length: %d).\n",buf,strlen(buf));

	if (buf[0] == '\0') {
	    warn("Invalid Request\n");
	    goto error;
	}

	username = strwordtok(buf, &t);
	for (n = 0; (group = strwordtok(NULL, &t)) != NULL; n++)
	    groups[n] = group;
	groups[n] = NULL;

	if (Valid_Groups(username, groups)) {
	    printf ("OK\n");
	} else {
error:
	    printf ("ERR\n");
	}
	err = 0;
    }
    return 0;
}
