
/*
 * $Id: client_side.cc,v 1.69 1996/11/27 22:19:18 wessels Exp $
 *
 * DEBUG: section 33    Client-side Routines
 * AUTHOR: Duane Wessels
 *
 * SQUID Internet Object Cache  http://squid.nlanr.net/Squid/
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
static void icpHandleIMSReply _PARAMS((int fd, StoreEntry * entry, void *data));
static void clientLookupDstIPDone _PARAMS((int fd, const ipcache_addrs *, void *data));
static void clientLookupSrcFQDNDone _PARAMS((int fd, const char *fqdn, void *data));


static void
clientLookupDstIPDone(int fd, const ipcache_addrs * ia, void *data)
{
    icpStateData *icpState = data;
    debug(33, 5, "clientLookupDstIPDone: FD %d, '%s'\n",
	fd,
	icpState->url);
    icpState->aclChecklist->state[ACL_DST_IP] = ACL_LOOKUP_DONE;
    if (ia) {
	icpState->aclChecklist->dst_addr = ia->in_addrs[0];
	debug(33, 5, "clientLookupDstIPDone: %s is %s\n",
	    icpState->request->host,
	    inet_ntoa(icpState->aclChecklist->dst_addr));
    }
    clientAccessCheck(icpState, icpState->aclHandler);
}

static void
clientLookupSrcFQDNDone(int fd, const char *fqdn, void *data)
{
    icpStateData *icpState = data;
    debug(33, 5, "clientLookupSrcFQDNDone: FD %d, '%s', FQDN %s\n",
	fd,
	icpState->url,
	fqdn ? fqdn : "NULL");
    icpState->aclChecklist->state[ACL_SRC_DOMAIN] = ACL_LOOKUP_DONE;
    clientAccessCheck(icpState, icpState->aclHandler);
}

static void
clientLookupIdentDone(void *data)
{
    icpStateData *icpState = data;
    clientAccessCheck(icpState, icpState->aclHandler);
}

#if USE_PROXY_AUTH
/* return 1 if allowed, 0 if denied */
static int
clientProxyAuthCheck(icpStateData * icpState)
{
    const char *proxy_user;

    /* Check that the user is allowed to access via this proxy-cache
     * don't restrict if they're accessing a local domain or
     * an object of type cacheobj:// */
    if (Config.proxyAuthFile == NULL)
	return 1;
    if (urlParseProtocol(icpState->url) == PROTO_CACHEOBJ)
	return 1;
    if (Config.proxyAuthIgnoreDomain != NULL)
	if (matchDomainName(Config.proxyAuthIgnoreDomain, icpState->request->host))
	    return 1;
    proxy_user = proxyAuthenticate(icpState->request_hdr);
    xstrncpy(icpState->ident.ident, proxy_user, ICP_IDENT_SZ);
    debug(33, 6, "jrmt: user = %s\n", icpState->ident.ident);

    if (strcmp(icpState->ident.ident, dash_str) == 0)
	return 0;
    return 1;
}
#endif /* USE_PROXY_AUTH */

void
clientAccessCheck(icpStateData * icpState, void (*handler) (icpStateData *, int))
{
    int answer = 1;
    request_t *r = icpState->request;
    aclCheck_t *ch = NULL;
    char *browser = NULL;

    if (Config.identLookup && icpState->ident.state == IDENT_NONE) {
	icpState->aclHandler = handler;
	identStart(-1, icpState, clientLookupIdentDone);
	return;
    }
    if (icpState->aclChecklist == NULL) {
	icpState->aclChecklist = xcalloc(1, sizeof(aclCheck_t));
	icpState->aclChecklist->src_addr = icpState->peer.sin_addr;
	icpState->aclChecklist->request = requestLink(icpState->request);
	browser = mime_get_header(icpState->request_hdr, "User-Agent");
	if (browser != NULL) {
	    xstrncpy(icpState->aclChecklist->browser, browser, BROWSERNAMELEN);
	} else {
	    icpState->aclChecklist->browser[0] = '\0';
	}
    }
#if USE_PROXY_AUTH
    if (clientProxyAuthCheck(icpState) == 0) {
	char *wbuf = NULL;
	int fd = icpState->fd;
	debug(33, 4, "Proxy Denied: %s\n", icpState->url);
	icpState->log_type = ERR_PROXY_DENIED;
	icpState->http_code = 407;
	wbuf = xstrdup(proxy_denied_msg(icpState->http_code,
		icpState->method,
		icpState->url,
		fd_table[fd].ipaddr));
	icpSendERROR(fd, icpState->log_type, wbuf, icpState, icpState->http_code);
	safe_free(icpState->aclChecklist);
	return;
    }
#endif /* USE_PROXY_AUTH */

    ch = icpState->aclChecklist;
    icpState->aclHandler = handler;
    if (httpd_accel_mode && !Config.Accel.withProxy && r->protocol != PROTO_CACHEOBJ) {
	/* this cache is an httpd accelerator ONLY */
	if (icpState->accel == 0)
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

void
clientAccessCheckDone(icpStateData * icpState, int answer)
{
    int fd = icpState->fd;
    char *buf = NULL;
    char *redirectUrl = NULL;
    debug(33, 5, "clientAccessCheckDone: '%s' answer=%d\n", icpState->url, answer);
    if (answer) {
	urlCanonical(icpState->request, icpState->url);
	redirectStart(fd, icpState, clientRedirectDone, icpState);
    } else {
	debug(33, 5, "Access Denied: %s\n", icpState->url);
	redirectUrl = aclGetDenyInfoUrl(&DenyInfoList, AclMatchedName);
	if (redirectUrl) {
	    icpState->http_code = 302,
		buf = access_denied_redirect(icpState->http_code,
		icpState->method,
		icpState->url,
		fd_table[fd].ipaddr,
		redirectUrl);
	} else {
	    icpState->http_code = 400;
	    buf = access_denied_msg(icpState->http_code,
		icpState->method,
		icpState->url,
		fd_table[fd].ipaddr);
	}
	icpSendERROR(fd, LOG_TCP_DENIED, buf, icpState, icpState->http_code);
    }
}

static void
clientRedirectDone(void *data, char *result)
{
    icpStateData *icpState = data;
    int fd = icpState->fd;
    request_t *new_request = NULL;
    request_t *old_request = icpState->request;
    debug(33, 5, "clientRedirectDone: '%s' result=%s\n", icpState->url,
	result ? result : "NULL");
    if (result)
	new_request = urlParse(old_request->method, result);
    if (new_request) {
	safe_free(icpState->url);
	icpState->url = xstrdup(result);
	new_request->http_ver = old_request->http_ver;
	requestUnlink(old_request);
	icpState->request = requestLink(new_request);
	urlCanonical(icpState->request, icpState->url);
    }
    icpParseRequestHeaders(icpState);
    fd_note(fd, icpState->url);
    if (!BIT_TEST(icpState->request->flags, REQ_PROXY_KEEPALIVE)) {
	commSetSelect(fd,
	    COMM_SELECT_READ,
	    icpDetectClientClose,
	    (void *) icpState,
	    0);
    }
    icpProcessRequest(fd, icpState);
}

#if USE_PROXY_AUTH
/* Check the modification time on the file that holds the proxy
 * passwords every 'n' seconds, and if it has changed, reload it
 */
#define CHECK_PROXY_FILE_TIME 300

const char *
proxyAuthenticate(const char *headers)
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

    /* Look for Proxy-authorization: Basic in the
     * headers sent by the client
     */
    if ((s = mime_get_header(headers, "Proxy-authorization:")) == NULL) {
	debug(33, 5, "jrmt: Can't find authorization header\n");
	return (dash_str);
    }
    /* Skip the 'Basic' part */
    s += strlen(" Basic");
    sent_userandpw = xstrdup(s);
    strtok(sent_userandpw, "\n");	/* Trim trailing \n before decoding */
    clear_userandpw = uudecode(sent_userandpw);
    xfree(sent_userandpw);

    xstrncpy(sent_user, clear_userandpw, ICP_IDENT_SZ);
    strtok(sent_user, ":");	/* Remove :password */
    debug(33, 5, "jrmt: user = %s\n", sent_user);

    /* Look at the Last-modified time of the proxy.passwords
     * file every five minutes, to see if it's been changed via
     * a cgi-bin script, etc. If so, reload a fresh copy into memory
     */

    current_time = time(NULL);

    if ((current_time - last_time) > CHECK_PROXY_FILE_TIME) {
	debug(33, 5, "jrmt: checking password file %s hasn't changed\n", Config.proxyAuthFile);

	if (stat(Config.proxyAuthFile, &buf) == 0) {
	    if (buf.st_mtime != change_time) {
		debug(33, 0, "jrmt: reloading changed proxy authentication password file %s \n", Config.proxyAuthFile);
		change_time = buf.st_mtime;

		if (validated != 0) {
		    debug(33, 5, "jrmt: invalidating old entries\n");
		    for (i = 0, hashr = hash_first(validated); hashr; hashr = hash_next(validated)) {
			debug(33, 6, "jrmt: deleting %s\n", hashr->key);
			hash_delete(validated, hashr->key);
		    }
		} else {
		    /* First time around, 7921 should be big enough */
		    if ((validated = hash_create(urlcmp, 7921, hash_string)) < 0) {
			debug(33, 1, "ERK: can't create hash table. Turning auth off");
			xfree(Config.proxyAuthFile);
			Config.proxyAuthFile = NULL;
			return (dash_str);
		    }
		}

		passwords = xmalloc((size_t) buf.st_size + 2);
		f = fopen(Config.proxyAuthFile, "r");
		fread(passwords, (size_t) buf.st_size, 1, f);
		*(passwords + buf.st_size) = '\0';
		strcat(passwords, "\n");
		fclose(f);

		user = strtok(passwords, ":");
		passwd = strtok(NULL, "\n");

		debug(33, 5, "jrmt: adding new passwords to hash table\n");
		while (user != NULL) {
		    if (strlen(user) > 1 && strlen(passwd) > 1) {
			debug(33, 6, "jrmt: adding %s, %s to hash table\n", user, passwd);
			hash_insert(validated, xstrdup(user), (void *) xstrdup(passwd));
		    }
		    user = strtok(NULL, ":");
		    passwd = strtok(NULL, "\n");
		}

		xfree(passwords);
	    }
	} else {
	    debug(33, 1, "ERK: can't access proxy_auth file %s. Turning authentication off", Config.proxyAuthFile);
	    xfree(Config.proxyAuthFile);
	    Config.proxyAuthFile = NULL;
	    return (dash_str);
	}
    }
    last_time = current_time;

    hashr = hash_lookup(validated, sent_user);
    if (hashr == NULL) {
	/* User doesn't exist; deny them */
	debug(33, 4, "jrmt: user %s doesn't exist\n", sent_user);
	xfree(clear_userandpw);
	return (dash_str);
    }
    passwd = strstr(clear_userandpw, ":");
    passwd++;

    /* See if we've already validated them */
    if (strcmp(hashr->item, passwd) == 0) {
	debug(33, 5, "jrmt: user %s previously validated\n", sent_user);
	xfree(clear_userandpw);
	return sent_user;
    }
    if (strcmp(hashr->item, (char *) crypt(passwd, hashr->item))) {
	/* Passwords differ, deny access */
	debug(33, 4, "jrmt: authentication failed: user %s passwords differ\n", sent_user);
	xfree(clear_userandpw);
	return (dash_str);
    }
    debug(33, 5, "jrmt: user %s validated\n", sent_user);
    hash_delete(validated, sent_user);
    hash_insert(validated, xstrdup(sent_user), (void *) xstrdup(passwd));

    xfree(clear_userandpw);
    return (sent_user);
}
#endif /* USE_PROXY_AUTH */

void
icpProcessExpired(int fd, void *data)
{
    icpStateData *icpState = data;
    char *url = icpState->url;
    char *request_hdr = icpState->request_hdr;
    StoreEntry *entry = NULL;

    debug(33, 3, "icpProcessExpired: FD %d '%s'\n", fd, icpState->url);

    BIT_SET(icpState->request->flags, REQ_REFRESH);
    icpState->old_entry = icpState->entry;
    entry = storeCreateEntry(url,
	request_hdr,
	icpState->req_hdr_sz,
	icpState->request->flags,
	icpState->method);
    /* NOTE, don't call storeLockObject(), storeCreateEntry() does it */
    storeClientListAdd(entry, fd, 0);

    entry->lastmod = icpState->old_entry->lastmod;
    debug(33, 5, "icpProcessExpired: setting lmt = %d\n",
	entry->lastmod);

    entry->refcount++;		/* EXPIRED CASE */
    icpState->entry = entry;
    icpState->offset = 0;
    /* Register with storage manager to receive updates when data comes in. */
    storeRegister(entry, fd, icpHandleIMSReply, (void *) icpState);
    protoDispatch(fd, url, icpState->entry, icpState->request);
}


static void
icpHandleIMSReply(int fd, StoreEntry * entry, void *data)
{
    icpStateData *icpState = data;
    MemObject *mem = entry->mem_obj;
    char *hbuf;
    int len;
    int unlink_request = 0;
    StoreEntry *oldentry;
    debug(33, 3, "icpHandleIMSReply: FD %d '%s'\n", fd, entry->url);
    /* unregister this handler */
    if (entry->store_status == STORE_ABORTED) {
	debug(33, 3, "icpHandleIMSReply: ABORTED/%s '%s'\n",
	    log_tags[entry->mem_obj->abort_code], entry->url);
	/* We have an existing entry, but failed to validate it,
	 * so send the old one anyway */
	icpState->log_type = LOG_TCP_REFRESH_FAIL_HIT;
	storeUnregister(entry, fd);
	storeUnlockObject(entry);
	icpState->entry = icpState->old_entry;
	icpState->entry->refcount++;
    } else if (mem->reply->code == 0) {
	debug(33, 3, "icpHandleIMSReply: Incomplete headers for '%s'\n",
	    entry->url);
	storeRegister(entry,
	    fd,
	    icpHandleIMSReply,
	    (void *) icpState);
	return;
    } else if (mem->reply->code == 304 && !BIT_TEST(icpState->request->flags, REQ_IMS)) {
	/* We initiated the IMS request, the client is not expecting
	 * 304, so put the good one back.  First, make sure the old entry
	 * headers have been loaded from disk. */
	oldentry = icpState->old_entry;
	if (oldentry->mem_obj->e_current_len == 0) {
	    storeRegister(entry,
		fd,
		icpHandleIMSReply,
		(void *) icpState);
	    return;
	}
	icpState->log_type = LOG_TCP_REFRESH_HIT;
	hbuf = get_free_8k_page();
	storeClientCopy(oldentry, 0, 8191, hbuf, &len, fd);
	if (oldentry->mem_obj->request == NULL) {
	    oldentry->mem_obj->request = requestLink(mem->request);
	    unlink_request = 1;
	}
	storeUnregister(entry, fd);
	storeUnlockObject(entry);
	entry = icpState->entry = oldentry;
	if (mime_headers_end(hbuf)) {
	    httpParseReplyHeaders(hbuf, entry->mem_obj->reply);
	    timestampsSet(entry);
	} else {
	    debug(33, 1, "icpHandleIMSReply: No end-of-headers, len=%d\n", len);
	    debug(33, 1, "  --> '%s'\n", entry->url);
	}
	entry->timestamp = squid_curtime;
	put_free_8k_page(hbuf);
	if (unlink_request) {
	    requestUnlink(entry->mem_obj->request);
	    entry->mem_obj->request = NULL;
	}
    } else {
	/* the client can handle this reply, whatever it is */
	icpState->log_type = LOG_TCP_REFRESH_MISS;
	if (mem->reply->code == 304) {
	    icpState->old_entry->timestamp = squid_curtime;
	    icpState->old_entry->refcount++;
	    icpState->log_type = LOG_TCP_REFRESH_HIT;
	}
	storeUnregister(icpState->old_entry, fd);
	storeUnlockObject(icpState->old_entry);
    }
    icpState->old_entry = NULL;	/* done with old_entry */
    icpSendMoreData(fd, icpState);	/* give data to the client */
}
