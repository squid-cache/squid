
/*
 * $Id: client_side.cc,v 1.11 1996/08/26 23:27:12 wessels Exp $
 *
 * DEBUG: section 33    Client-side Routines
 * AUTHOR: Duane Wessels
 *
 * SQUID Internet Object Cache  http://www.nlanr.net/Squid/
 * --------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from the
 *  Internet community.  Development is led by Duane Wessels of the
 *  National Laboratory for Applied Network Research and funded by
 *  the National Science Foundation.
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
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *  
 */

#include "squid.h"

static void clientRedirectDone _PARAMS((void *data, char *result));

static int clientLookupDstIPDone(fd, hp, data)
     int fd;
     struct hostent *hp;
     void *data;
{
    icpStateData *icpState = data;
    debug(33, 5, "clientLookupDstIPDone: FD %d, '%s'\n",
	fd,
	icpState->url);
    icpState->aclChecklist->state[ACL_DST_IP] = ACL_LOOKUP_DONE;
    if (hp) {
	xmemcpy(&icpState->aclChecklist->dst_addr.s_addr,
	    *(hp->h_addr_list),
	    hp->h_length);
	debug(33, 5, "clientLookupDstIPDone: %s is %s\n",
	    icpState->request->host,
	    inet_ntoa(icpState->aclChecklist->dst_addr));
    }
    clientAccessCheck(icpState, icpState->aclHandler);
    return 1;
}

static void clientLookupSrcFQDNDone(fd, fqdn, data)
     int fd;
     char *fqdn;
     void *data;
{
    icpStateData *icpState = data;
    debug(33, 5, "clientLookupSrcFQDNDone: FD %d, '%s', FQDN %s\n",
	fd,
	icpState->url,
	fqdn ? fqdn : "NULL");
    icpState->aclChecklist->state[ACL_SRC_DOMAIN] = ACL_LOOKUP_DONE;
    clientAccessCheck(icpState, icpState->aclHandler);
}

static void clientLookupIdentDone(data)
     void *data;
{
}

#if USE_PROXY_AUTH
/* return 1 if allowed, 0 if denied */
static int clientProxyAuthCheck(icpState)
     icpStateData *icpState;
{
    char *proxy_user;

    /* Check that the user is allowed to access via this proxy-cache
     * don't restrict if they're accessing a local domain or
     * an object of type cacheobj:// */
    if (Config.proxyAuthFile == NULL)
	return 1;
    if (strstr(icpState->url, Config.proxyAuthIgnoreDomain))
	return 1;
    if (urlParseProtocol(icpState->url) == PROTO_CACHEOBJ)
	return 1;

    proxy_user = proxyAuthenticate(icpState->request_hdr);
    strncpy(icpState->ident, proxy_user, ICP_IDENT_SZ);
    debug(12, 6, "jrmt: user = %s\n", icpState->ident);

    if (strcmp(icpState->ident, dash_str) == 0)
	return 0;
    return 1;
}
#endif /* USE_PROXY_AUTH */

void clientAccessCheck(icpState, handler)
     icpStateData *icpState;
     void (*handler) _PARAMS((icpStateData *, int));
{
    int answer = 1;
    request_t *r = icpState->request;
    aclCheck_t *ch = NULL;

    if (icpState->aclChecklist == NULL) {
	icpState->aclChecklist = xcalloc(1, sizeof(aclCheck_t));
	icpState->aclChecklist->src_addr = icpState->peer.sin_addr;
	icpState->aclChecklist->request = requestLink(icpState->request);
    }
#if USE_PROXY_AUTH
    if (clientProxyAuthCheck == 0) {
	char *wbuf = NULL;
	int fd = icpState->fd;
	debug(12, 4, "Proxy Denied: %s\n", icpState->url);
	icpState->log_type = ERR_PROXY_DENIED;
	icpState->http_code = 407;
	wbuf = xstrdup(proxy_denied_msg(icpState->http_code,
		icpState->method,
		icpState->url,
		fd_table[fd].ipaddr));
	icpSendERROR(fd, icpState->log_type, wbuf, icpState, icpState->http_code);
	return;
    }
#endif /* USE_PROXY_AUTH */

    ch = icpState->aclChecklist;
    icpState->aclHandler = handler;
    if (httpd_accel_mode && !Config.Accel.withProxy && r->protocol != PROTO_CACHEOBJ) {
	/* this cache is an httpd accelerator ONLY */
	if (!BIT_TEST(icpState->flags, REQ_ACCEL))
	    answer = 0;
    } else {
	answer = aclCheck(HTTPAccessList, ch);
	if (ch->state[ACL_DST_IP] == ACL_LOOKUP_NEED) {
	    ch->state[ACL_DST_IP] = ACL_LOOKUP_PENDING;		/* first */
	    ipcache_nbgethostbyname(icpState->request->host,
		icpState->fd,
		clientLookupDstIPDone,
		icpState);
	    return;
	} else if (ch->state[ACL_SRC_DOMAIN] == ACL_LOOKUP_NEED) {
	    ch->state[ACL_SRC_DOMAIN] = ACL_LOOKUP_PENDING;	/* first */
	    fqdncache_nbgethostbyaddr(icpState->peer.sin_addr,
		icpState->fd,
		clientLookupSrcFQDNDone,
		icpState);
	    return;
	}
    }
    requestUnlink(icpState->aclChecklist->request);
    safe_free(icpState->aclChecklist);
    icpState->aclHandler = NULL;
    handler(icpState, answer);
}

void clientAccessCheckDone(icpState, answer)
     icpStateData *icpState;
     int answer;
{
    int fd = icpState->fd;
    char *buf = NULL;
    debug(33, 5, "clientAccessCheckDone: '%s' answer=%d\n", icpState->url, answer);
    if (answer) {
	urlCanonical(icpState->request, icpState->url);
	redirectStart(fd, icpState, clientRedirectDone, icpState);
    } else {
	debug(33, 5, "Access Denied: %s\n", icpState->url);
	buf = access_denied_msg(icpState->http_code = 400,
	    icpState->method,
	    icpState->url,
	    fd_table[fd].ipaddr);
	icpSendERROR(fd, LOG_TCP_DENIED, buf, icpState, 403);
    }
}

static void clientRedirectDone(data, result)
     void *data;
     char *result;
{
    icpStateData *icpState = data;
    int fd = icpState->fd;
    request_t *new_request = NULL;
    debug(33, 5, "clientRedirectDone: '%s' result=%s\n", icpState->url,
	result ? result : "NULL");
    if (result)
	new_request = urlParse(icpState->request->method, result);
    if (new_request) {
	safe_free(icpState->url);
	icpState->url = xstrdup(result);
	requestUnlink(icpState->request);
	icpState->request = requestLink(new_request);
	urlCanonical(icpState->request, icpState->url);
    }
    icpParseRequestHeaders(icpState);
    fd_note(fd, icpState->url);
    comm_set_select_handler(fd,
	COMM_SELECT_READ,
	(PF) icpDetectClientClose,
	(void *) icpState);
    icp_hit_or_miss(fd, icpState);
#if USE_PROXY_AUTH
}

/* Check the modification time on the file that holds the proxy
 * passwords every 'n' seconds, and if it has changed, reload it
 */
#define CHECK_PROXY_FILE_TIME 300

char *proxyAuthenticate(char *headers)
{
    /* Keep the time measurements and the hash
     * table of users and passwords handy */
    static time_t last_time = 0;
    static time_t change_time = 0;
    static HashID validated = 0;
    static char *passwords = NULL;
    LOCAL_ARRAY(char, sent_user, ICP_IDENT_SZ);

    char *s = NULL;
    char *sent_userandpw = NULL;
    char *user = NULL;
    char *passwd = NULL;
    char *clear_userandpw = NULL;
    time_t current_time;
    struct stat buf;
    int i;
    hash_link *hashr = NULL;
    FILE *f = NULL;

    /* Look for Proxy-[Aa]uthorization: Basic in the
     * headers sent by the client
     */
    if ((s = mime_get_header(headers, "Proxy-authorization:")) == NULL) {
	/* Check for MS Internet Explorer too, as well as Netscape
	 * FIXME: Need a version of mime_get_header that uses strcasecmp()
	 */
	if ((s = mime_get_header(headers, "Proxy-Authorization:")) == NULL) {
	    debug(12, 5, "jrmt: Can't find authorization header\n");
	    return (dash_str);
	}
    }
    /* Skip the 'Basic' part */
    s += strlen(" Basic");
    sent_userandpw = xstrdup(s);
    strtok(sent_userandpw, "\n");	/* Trim trailing \n before decoding */
    clear_userandpw = uudecode(sent_userandpw);
    xfree(sent_userandpw);

    strncpy(sent_user, clear_userandpw, ICP_IDENT_SZ);
    strtok(sent_user, ":");	/* Remove :password */
    debug(12, 5, "jrmt: user = %s\n", sent_user);

    /* Look at the Last-modified time of the proxy.passwords
     * file every ten seconds, to see if it's been changed via
     * a cgi-bin script, etc. If so, reload a fresh copy into memory
     */

    current_time = time(NULL);

    if ((current_time - last_time) > CHECK_PROXY_FILE_TIME) {
	debug(12, 5, "jrmt: checking password file %s hasn't changed\n", Config.proxyAuthFile);

	if (stat(Config.proxyAuthFile, &buf) == 0) {
	    if (buf.st_mtime != change_time) {
		debug(12, 0, "jrmt: reloading changed proxy authentication password file %s \n", Config.proxyAuthFile);
		change_time = buf.st_mtime;

		if (passwords != NULL)
		    xfree(passwords);

		if (validated != 0) {
		    debug(12, 5, "jrmt: invalidating old entries\n");
		    for (i = 0, hashr = hash_first(validated); hashr; hashr = hash_next(validated)) {
			debug(12, 6, "jrmt: deleting %s\n", hashr->key);
			hash_delete(validated, hashr->key);
		    }
		} else {
		    /* First time around, 7921 should be big enough for GDS :-) */
		    if ((validated = hash_create(urlcmp, 7921, hash_string)) < 0) {
			debug(1, 1, "ERK: can't create hash table. Turning auth off");
			Config.proxyAuthOn = 0;
			return (dash_str);
		    }
		}

		passwords = xmalloc((size_t) buf.st_size + 2);
		f = fopen(Config.proxyAuthFile, "r");
		fread(passwords, buf.st_size, 1, f);
		*(passwords + buf.st_size) = '\0';
		strcat(passwords, "\n");
		fclose(f);

		user = strtok(passwords, ":");
		passwd = strtok(NULL, "\n");

		debug(12, 5, "jrmt: adding new passwords to hash table\n");
		while (user != NULL) {
		    if (strlen(user) > 1 && strlen(passwd) > 1) {
			debug(12, 6, "jrmt: adding %s, %s to hash table\n", user, passwd);
			hash_insert(validated, user, (void *) passwd);
		    }
		    user = strtok(NULL, ":");
		    passwd = strtok(NULL, "\n");
		}
	    }
	} else {
	    debug(1, 1, "ERK: can't access proxy_auth_file %s. Turning authentication off until SIGHUPed", Config.proxyAuthFile);
	    Config.proxyAuthOn = 0;
	    return (dash_str);
	}
    }
    last_time = current_time;

    hashr = hash_lookup(validated, sent_user);
    if (hashr == NULL) {
	/* User doesn't exist; deny them */
	debug(12, 4, "jrmt: user %s doesn't exist\n", sent_user);
	xfree(clear_userandpw);
	return (dash_str);
    }
    /* See if we've already validated them */
    if (strcmp(hashr->item, "OK") == 0) {
	debug(12, 5, "jrmt: user %s previously validated\n", sent_user);
	xfree(clear_userandpw);
	return sent_user;
    }
    passwd = strstr(clear_userandpw, ":");
    passwd++;

    if (strcmp(hashr->item, (char *) crypt(passwd, hashr->item))) {
	/* Passwords differ, deny access */
	debug(12, 4, "jrmt: authentication failed: user %s passwords differ\n", sent_user);
	debug(12, 6, "jrmt: password given: %s, actual %s\n", passwd, hashr->item);
	xfree(clear_userandpw);
	return (dash_str);
    }
    debug(12, 5, "jrmt: user %s validated\n", sent_user);
    hash_insert(validated, sent_user, (void *) "OK");

    xfree(clear_userandpw);
    return (sent_user);
#endif /* USE_PROXY_AUTH */
}
