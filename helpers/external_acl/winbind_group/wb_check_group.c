/*
 * winbind_group: lookup group membership in a Windows NT/2000 domain
 *
 * (C)2002,2003 Guido Serassio - Acme Consulting S.r.l.
 *
 * Authors:
 *  Guido Serassio <guido.serassio@acmeconsulting.it>
 *  Acme Consulting S.r.l., Italy <http://www.acmeconsulting.it>
 *
 * With contributions from others mentioned in the change history section
 * below.
 *
 * In part based on check_group by Rodrigo Albani de Campos and wbinfo
 * from Samba Project.
 *
 * Dependencies: Samba 2.2.4 or later with Winbindd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111, USA.
 *
 * History:
 *
 * Version 1.21
 * 15-08-2004 Henrik Nordstrom
 * 		Helper protocol changed to use URL escaped strings in Squid-3.0
 * Version 1.20
 * 10-05-2003 Roberto Moreda
 *              Added support for domain-qualified group Microsoft notation
 *              (DOMAIN\Groupname). 
 *            Guido Serassio
 *              More debug info.
 *              Updated documentation.
 * Version 1.10
 * 26-04-2003 Guido Serassio
 *              Added option for case insensitive group name comparation.
 *              More debug info.
 *              Updated documentation.
 * 21-03-2003 Nicolas Chaillot
 *              Segfault bug fix (Bugzilla #574)
 * Version 1.0
 * 02-07-2002 Guido Serassio
 *              Using the main function from check_group and sections
 *              from wbinfo wrote winbind_group
 *
 * This is a helper for the external ACL interface for Squid Cache
 * 
 * It reads from the standard input the domain username and a list of
 * groups and tries to match it against the groups membership of the
 * specified username.
 *
 * Returns `OK' if the user belongs to a group or `ERR' otherwise, as
 * described on http://devel.squid-cache.org/external_acl/config.html
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
#include "wb_common.h"

#define BUFSIZE 8192		/* the stdin buffer size */
char debug_enabled=0;
const char *myname;
pid_t mypid;
static int use_case_insensitive_compare=0;

static int strCaseCmp (const char *s1, const char *s2)
{
    while (*s1 && toupper (*s1) == toupper (*s2)) s1++, s2++;
    return *s1 - *s2;
}

/* Convert sid to string */

static char * wbinfo_lookupsid(char * group, char *sid)
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

    strcpy(group,response.data.name.dom_name);
    strcat(group,"\\");
    strcat(group,response.data.name.name);
    return group;
}

/* Convert gid to sid */

static char * wbinfo_gid_to_sid(char * sid, gid_t gid)
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
    const char *wgroup;

    while (*array) {
	/* If the groups we want to match are specified as 'group', and
	 * not as 'DOMAIN\group' we strip the domain from the group to
	 * match against */
	if (strstr(*array,"\\") == NULL) {
	    wgroup = strstr(str,"\\") + 1;
	    debug("Stripping domain from group name %s\n", str); 
	} else {
	    wgroup = str;
	}
	
    	debug("Windows group: %s, Squid group: %s\n", wgroup, *array);
	if ((use_case_insensitive_compare ? strCaseCmp(wgroup, *array) : strcmp(wgroup, *array)) == 0)
	    return 0;
	array++;
    }
    return -1;
}

/* returns 1 on success, 0 on failure */
static int
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

    if (result != NSS_STATUS_SUCCESS) {
    	warn("Warning: Can't enum user groups.\n");
	return match;
    }	

    for (i = 0; i < response.data.num_entries; i++) {
    	if ((wbinfo_gid_to_sid(sid, (int)((gid_t *)response.extra_data)[i])) != NULL) {
    	    debug("SID: %s\n", sid);	
	    if (wbinfo_lookupsid(group,sid) == NULL) {
	    	warn("Can't lookup group SID.\n");
    		break;
    	    }
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
    fprintf(stderr,"Usage: %s [-c] [-d] [-h]\n"
	    	" -c      use case insensitive compare\n"
	    	" -d      enable debugging\n"
		" -h      this message\n",
		program);
}

static void
process_options(int argc, char *argv[])
{
    int opt;

    opterr = 0;
    while (-1 != (opt = getopt(argc, argv, "cdh"))) {
	switch (opt) {
	case 'c':
	    use_case_insensitive_compare = 1;
	    break;
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

void
check_winbindd()
{
    NSS_STATUS r;
    int retry=10;
    struct winbindd_request request;
    struct winbindd_response response;
    do {
	r = winbindd_request(WINBINDD_INTERFACE_VERSION, &request, &response);
	if (r != NSS_STATUS_SUCCESS)
	    retry--; 
    } while (r != NSS_STATUS_SUCCESS && retry);
    if (r != NSS_STATUS_SUCCESS) {
	warn("Can't contact winbindd. Dying\n");
	exit(1);
    }
    if (response.data.interface_version != WINBIND_INTERFACE_VERSION) {
	warn("Winbind protocol mismatch. Align squid and samba. Dying\n");
	exit(1);
    }
}

int
main (int argc, char *argv[])
{
    char *p;
    char buf[BUFSIZE];
    char *username;
    char *group;
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
    if (use_case_insensitive_compare)
        debug("Warning: running in case insensitive mode !!!\n");
 
    check_winbindd();

    /* Main Loop */
    while (fgets (buf, sizeof(buf), stdin))
    {
	if (NULL == strchr(buf, '\n')) {
	    /* too large message received.. skip and deny */
	    fprintf(stderr, "%s: ERROR: Too large: %s\n", argv[0], buf);
	    while (fgets(buf, sizeof(buf), stdin)) {
		fprintf(stderr, "%s: ERROR: Too large..: %s\n", argv[0], buf);
		if (strchr(buf, '\n') != NULL)
		    break;
	    }
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

	username = strtok(buf, " ");
	for (n = 0; (group = strtok(NULL, " ")) != NULL; n++) {
	    rfc1738_unescape(group);
	    groups[n] = group;
	}
	groups[n] = NULL;

        if (NULL == username) {
            warn("Invalid Request\n");
            goto error;
        }
	rfc1738_unescape(username);

	if (Valid_Groups(username, groups)) {
	    printf ("OK\n");
	} else {
error:
	    printf ("ERR\n");
	}
    }
    return 0;
}
